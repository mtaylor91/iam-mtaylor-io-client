module IAM.Command.Delete.Group
  ( deleteGroup
  , deleteGroupOptions
  , DeleteGroup(..)
  ) where

import Data.Text
import Data.UUID
import Options.Applicative
import Text.Read

import IAM.Client.Util
import IAM.GroupIdentifier (GroupId(..), GroupIdentifier(..))
import qualified IAM.Client


newtype DeleteGroup = DeleteGroup
  { deleteGroupGroupId :: Text
  } deriving (Show)


deleteGroup :: DeleteGroup -> IO ()
deleteGroup deleteGroupInfo =
  case readMaybe (unpack $ deleteGroupGroupId deleteGroupInfo) of
    Just uuid -> deleteGroupByUUID uuid
    Nothing -> deleteGroupByName $ deleteGroupGroupId deleteGroupInfo


deleteGroupByName :: Text -> IO ()
deleteGroupByName = deleteGroupById . GroupName


deleteGroupByUUID :: UUID -> IO ()
deleteGroupByUUID = deleteGroupById . GroupId . GroupUUID


deleteGroupById :: GroupIdentifier -> IO ()
deleteGroupById gid = do
  iamConfig <- IAM.Client.iamClientConfigEnv
  iamClient <- IAM.Client.newIAMClient iamConfig

  let grpClient = IAM.Client.mkGroupClient gid
  res <- IAM.Client.iamRequest iamClient $ IAM.Client.deleteGroup grpClient
  case res of
    Left err -> handleClientError err
    Right _ -> return ()


deleteGroupOptions :: Parser DeleteGroup
deleteGroupOptions = DeleteGroup
  <$> argument str
      ( metavar "GROUP_ID"
     <> help "The name or uuid of the group to delete."
      )
