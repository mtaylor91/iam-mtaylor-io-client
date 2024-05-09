{-# LANGUAGE OverloadedStrings #-}
module IAM.Client.Auth
  ( clientAuthInfo
  , ClientAuth(..)
  , setClientSessionToken
  ) where

import Control.Concurrent.STM
import Control.Exception
import Crypto.Sign.Ed25519
import Data.ByteString hiding (pack, unpack)
import Data.ByteString.Base64.URL
import Data.CaseInsensitive
import Data.Functor
import Data.Text
import Data.Text.Encoding
import Data.UUID
import Data.UUID.V4
import Network.HTTP.Client
import System.IO.Unsafe

import IAM.Authentication
import IAM.Config


newtype ClientAuth = ClientAuth { clientAuth :: Request -> IO Request }


clientSessionToken :: TVar (Maybe Text)
clientSessionToken = unsafePerformIO $ newTVarIO Nothing
{-# NOINLINE clientSessionToken #-}


getClientSessionToken :: IO (Maybe Text)
getClientSessionToken = f =<< readTVarIO clientSessionToken where
  f :: Maybe Text -> IO (Maybe Text)
  f (Just token) = return $ Just token
  f Nothing = do
    mToken <- configMaybeSessionToken <&> fmap pack
    case mToken of
      Nothing -> return Nothing
      Just token -> do
        setClientSessionToken token
        return $ Just token


setClientSessionToken :: Text -> IO ()
setClientSessionToken = atomically . writeTVar clientSessionToken . Just


clientAuthInfo :: IO ClientAuth
clientAuthInfo = do
  userId <- configUserIdentifier
  secretKey <- configSecretKey
  case decodeSecretKey $ pack secretKey of
    Nothing ->
      throw $ userError "Invalid secret key"
    Just secretKey' ->
      return $ mkClientAuth userId secretKey'


mkClientAuth :: String -> SecretKey -> ClientAuth
mkClientAuth userId secretKey = ClientAuth $ \req -> do
  maybeSessionToken <- getClientSessionToken
  case lookup "Authorization" $ requestHeaders req of
    Just _ -> return req
    Nothing -> do
      requestId <- nextRandom
      let userId' = pack userId
          publicKey = encodePublicKey secretKey
          authorization = authHeader reqStringToSign secretKey
          reqStringToSign = authStringToSign req requestId maybeSessionToken
      return $ req
        { requestHeaders = requestHeaders req ++
          authReqHeaders authorization userId' publicKey requestId maybeSessionToken
        }


encodePublicKey :: SecretKey -> Text
encodePublicKey = encodeBase64 . unPublicKey . toPublicKey


decodeSecretKey :: Text -> Maybe SecretKey
decodeSecretKey t =
  case decodeBase64 (encodeUtf8 t) of
    Left _ -> Nothing
    Right bs -> Just $ SecretKey bs


authHeader :: Text -> SecretKey -> ByteString
authHeader reqStringToSign secretKey = "Signature " <> encodeUtf8 (encodeBase64 sig)
  where Signature sig = dsign secretKey (encodeUtf8 reqStringToSign)


authStringToSign :: Request -> UUID -> Maybe Text -> Text
authStringToSign req reqId maybeSessionToken
  = decodeUtf8 $ stringToSign m h p q reqId maybeSessionToken
  where m = method req
        h = host req
        p = path req
        q = queryString req


authReqHeaders ::
  ByteString -> Text -> Text -> UUID -> Maybe Text ->  [(CI ByteString, ByteString)]
authReqHeaders authorization userId publicKey requestId Nothing =
  [ ("Authorization", authorization)
  , (headerPrefix' <> "-User-Id", encodeUtf8 userId)
  , (headerPrefix' <> "-Public-Key", encodeUtf8 publicKey)
  , (headerPrefix' <> "-Request-Id", encodeUtf8 $ pack $ toString requestId)
  ]
authReqHeaders authorization userId publicKey requestId (Just token) =
  (headerPrefix' <> "-Session-Token", encodeUtf8 token) :
  authReqHeaders authorization userId publicKey requestId Nothing


headerPrefix' :: CI ByteString
headerPrefix' = mk (encodeUtf8 $ pack headerPrefix)
