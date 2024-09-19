module IAM.Command.Get.User
  ( IAM.Command.Get.User.getUser
  ) where

import Data.Aeson
import Data.ByteString.Lazy (toStrict)
import Data.Text (Text, unpack)
import Data.Text.Encoding
import Data.UUID
import Text.Read
import qualified Data.Text as T

import IAM.Client
import IAM.Client.Util
import IAM.UserIdentifier (UserIdentifier(..), UserId(..))


getUser :: Maybe Text -> IO ()
getUser = maybe getCurrentUser getSpecifiedUser


getSpecifiedUser :: Text -> IO ()
getSpecifiedUser uid =
  case readMaybe (unpack uid) of
    Just uuid -> getUserByUUID uuid
    Nothing -> getUserByEmail uid


getCurrentUser :: IO ()
getCurrentUser = do
  iamConfig <- iamClientConfigEnv
  iamClient <- newIAMClient iamConfig
  result <- iamRequest iamClient IAM.Client.getCaller
  case result of
    Right user ->
      putStrLn $ T.unpack (decodeUtf8 $ toStrict $ encode $ toJSON user)
    Left err ->
      handleClientError err


getUserByUUID :: UUID -> IO ()
getUserByUUID uuid = getUserById $ UserIdentifier (Just $ UserUUID uuid) Nothing Nothing


getUserByEmail :: Text -> IO ()
getUserByEmail email = getUserById $ UserIdentifier Nothing Nothing (Just email)


getUserById :: UserIdentifier -> IO ()
getUserById uid = do
  iamConfig <- iamClientConfigEnv
  iamClient <- newIAMClient iamConfig
  let userClient = mkUserClient uid
  result <- iamRequest iamClient $ IAM.Client.getUser userClient
  case result of
    Right user ->
      putStrLn $ T.unpack (decodeUtf8 $ toStrict $ encode $ toJSON user)
    Left err ->
      handleClientError err
