{-# LANGUAGE OverloadedStrings #-}
module IAM.Client
  ( iamClientConfigEnv
  , newIAMClient
  , iamRequest
  , setSessionToken
  , IAMClient(..)
  , IAMClientConfig(..)
  , module IAM.Client.API
  ) where

import Control.Concurrent.STM
import Crypto.Sign.Ed25519
import Data.Text (Text, pack)
import Data.UUID.V4
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Servant.Client

import IAM.Client.API
import IAM.Client.Auth
import IAM.Config


data IAMClient = IAMClient
  { iamClientConfig :: IAMClientConfig
  , iamClientEnv :: ClientEnv
  , iamClientManager :: Manager
  , iamClientSessionTokenVar :: TVar (Maybe Text)
  }


data IAMClientConfig = IAMClientConfig
  { iamClientConfigBaseURL :: String
  , iamClientConfigUserIdentifier :: String
  , iamClientConfigSecretKey :: SecretKey
  , iamClientConfigSessionToken :: Maybe String
  }


iamClientConfigEnv :: IO IAMClientConfig
iamClientConfigEnv = do
  url <- configURL
  userId <- configUserIdentifier
  secretKeyString <- configSecretKey
  sessionToken <- configMaybeSessionToken
  case decodeSecretKey $ pack secretKeyString of
    Nothing -> error "Invalid secret key"
    Just secretKey -> return $ IAMClientConfig url userId secretKey sessionToken


newIAMClient :: IAMClientConfig -> IO IAMClient
newIAMClient config = do
  sessionTokenVar <- newTVarIO $ pack <$> iamClientConfigSessionToken config
  let r = requestAuth config sessionTokenVar
  url <- parseBaseUrl $ iamClientConfigBaseURL config
  mgr <- newManager tlsManagerSettings { managerModifyRequest = r }
  let clientEnv = mkClientEnv mgr url
  return $ IAMClient config clientEnv mgr sessionTokenVar


iamRequest :: IAMClient -> ClientM a -> IO (Either ClientError a)
iamRequest iamClient action = runClientM action $ iamClientEnv iamClient


requestAuth :: IAMClientConfig -> TVar (Maybe Text) -> Request -> IO Request
requestAuth config sessionTokenVar req = do
  case lookup "Authorization" $ requestHeaders req of
    Just _ -> return req
    Nothing -> do
      requestId <- nextRandom
      maybeSessionToken <- readTVarIO sessionTokenVar
      let userId' = pack $ iamClientConfigUserIdentifier config
          publicKey = encodePublicKey $ iamClientConfigSecretKey config
          authorization = authHeader reqStringToSign $ iamClientConfigSecretKey config
          reqStringToSign = authStringToSign req requestId maybeSessionToken
      return $ req
        { requestHeaders = requestHeaders req ++
          authReqHeaders authorization userId' publicKey requestId maybeSessionToken
        }


setSessionToken :: IAMClient -> Maybe Text -> IO ()
setSessionToken iamClient = atomically . writeTVar (iamClientSessionTokenVar iamClient)
