module IAM.Command.Delete.Group
  ( deleteGroup
  , deleteGroupOptions
  , DeleteGroup(..)
  ) where

import Data.Text
import Data.UUID
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Options.Applicative
import Servant.Client
import Text.Read

import IAM.Client.Auth
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
  url <- serverUrl
  auth <- clientAuthInfo
  mgr <- newManager tlsManagerSettings { managerModifyRequest = clientAuth auth }

  let grpClient = IAM.Client.mkGroupClient gid
  res <- runClientM (IAM.Client.deleteGroup grpClient) $ mkClientEnv mgr url
  case res of
    Left err -> handleClientError err
    Right _ -> return ()


deleteGroupOptions :: Parser DeleteGroup
deleteGroupOptions = DeleteGroup
  <$> argument str
      ( metavar "GROUP_ID"
     <> help "The name or uuid of the group to delete."
      )
