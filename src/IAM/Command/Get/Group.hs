module IAM.Command.Get.Group
  ( IAM.Command.Get.Group.getGroup
  ) where

import Data.Aeson
import Data.ByteString.Lazy (toStrict)
import Data.Text as T
import Data.Text.Encoding
import Data.UUID
import Text.Read

import IAM.Client
import IAM.Client.Util
import IAM.GroupIdentifier


getGroup :: Text -> IO ()
getGroup nameOrId =
  case readMaybe (unpack nameOrId) of
    Just uuid ->
      getGroupByUUID uuid
    Nothing ->
      getGroupByName nameOrId


getGroupByUUID :: UUID -> IO ()
getGroupByUUID = getGroupById . GroupId . GroupUUID


getGroupByName :: Text -> IO ()
getGroupByName = getGroupById . GroupName


getGroupById :: GroupIdentifier -> IO ()
getGroupById gid = do
  iamConfig <- iamClientConfigEnv
  iamClient <- newIAMClient iamConfig
  let groupClient = mkGroupClient gid
  result <- iamRequest iamClient $ IAM.Client.getGroup groupClient
  case result of
    Right group' ->
      putStrLn $ T.unpack (decodeUtf8 $ toStrict $ encode $ toJSON group')
    Left err ->
      handleClientError err
