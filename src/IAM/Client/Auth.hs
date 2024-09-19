{-# LANGUAGE OverloadedStrings #-}
module IAM.Client.Auth
  ( authHeader
  , authReqHeaders
  , authStringToSign
  , encodePublicKey
  , decodeSecretKey
  ) where

import Crypto.Sign.Ed25519
import Data.ByteString hiding (pack, unpack)
import Data.ByteString.Base64.URL
import Data.CaseInsensitive
import Data.Text
import Data.Text.Encoding
import Data.UUID
import Network.HTTP.Client

import IAM.Authentication
import IAM.Config


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
