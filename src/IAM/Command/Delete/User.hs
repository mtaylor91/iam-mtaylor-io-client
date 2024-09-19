module IAM.Command.Delete.User
  ( deleteUser
  , deleteUserOptions
  , DeleteUser(..)
  ) where

import Data.Text
import Data.UUID
import Options.Applicative
import Text.Read

import IAM.Client.Util
import IAM.UserIdentifier
import qualified IAM.Client


newtype DeleteUser = DeleteUser
  { deleteUserUserId :: Text
  } deriving (Show)


deleteUser :: DeleteUser -> IO ()
deleteUser deleteUserInfo =
  case readMaybe (unpack $ deleteUserUserId deleteUserInfo) of
    Just uuid -> deleteUserByUUID uuid
    Nothing -> deleteUserByEmail $ deleteUserUserId deleteUserInfo


deleteUserByEmail :: Text -> IO ()
deleteUserByEmail email = deleteUserById $ UserIdentifier Nothing Nothing (Just email)


deleteUserByUUID :: UUID -> IO ()
deleteUserByUUID uuid =
  deleteUserById $ UserIdentifier (Just $ UserUUID uuid) Nothing Nothing


deleteUserById :: UserIdentifier -> IO ()
deleteUserById uid = do
  iamConfig <- IAM.Client.iamClientConfigEnv
  iamClient <- IAM.Client.newIAMClient iamConfig

  let userClient = IAM.Client.mkUserClient uid
  res <- IAM.Client.iamRequest iamClient $ IAM.Client.deleteUser userClient
  case res of
    Left err -> handleClientError err
    Right _ -> return ()


deleteUserOptions :: Parser DeleteUser
deleteUserOptions = DeleteUser
  <$> argument str
      ( metavar "USER_ID"
     <> help "The email or uuid of the user to delete."
      )
