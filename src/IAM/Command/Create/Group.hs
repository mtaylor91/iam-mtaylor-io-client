module IAM.Command.Create.Group
  ( createGroup
  , createGroupOptions
  , CreateGroup(..)
  ) where

import Data.Text
import Data.Text.Encoding
import Data.UUID
import Data.UUID.V4
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Options.Applicative
import Servant.Client
import Text.Email.Validate
import Text.Read

import IAM.Client.Auth
import IAM.Client.Util
import IAM.Group
import IAM.GroupIdentifier
import IAM.Policy
import IAM.UserIdentifier
import qualified IAM.Client


data CreateGroup = CreateGroup
  { createGroupId :: !(Maybe Text)
  , createGroupPolicies :: ![Text]
  , createGroupUsers :: ![Text]
  } deriving (Show)


createGroup :: CreateGroup -> IO ()
createGroup createGroupInfo =
  case createGroupId createGroupInfo of
    Nothing -> createGroup' createGroupInfo
    Just groupIdentifier ->
      case readMaybe (unpack groupIdentifier) of
        Just uuid -> createGroupByUUID createGroupInfo uuid
        Nothing -> createGroupByName createGroupInfo groupIdentifier


createGroup' :: CreateGroup -> IO ()
createGroup' createGroupInfo = do
  uuid <- nextRandom
  createGroupByUUID createGroupInfo uuid


createGroupByName :: CreateGroup -> Text -> IO ()
createGroupByName createGroupInfo = createGroupById createGroupInfo . GroupName


createGroupByUUID :: CreateGroup -> UUID -> IO ()
createGroupByUUID createGroupInfo = createGroupById createGroupInfo . GroupId . GroupUUID


createGroupById :: CreateGroup -> GroupIdentifier -> IO ()
createGroupById createGroupInfo gident = do
  policies <- mapM translatePolicyId $ createGroupPolicies createGroupInfo
  users <- mapM translateUserId $ createGroupUsers createGroupInfo
  url <- serverUrl
  auth <- clientAuthInfo
  mgr <- newManager tlsManagerSettings { managerModifyRequest = clientAuth auth }

  gid <- case unGroupIdentifier gident of
    Right (GroupUUID uuid) -> return $ GroupUUID uuid
    Left _email -> GroupUUID <$> nextRandom

  let maybeName = unGroupIdentifierName gident
  let grp = Group gid maybeName users policies
  res <- runClientM (IAM.Client.createGroup grp) $ mkClientEnv mgr url
  case res of
    Left err -> handleClientError err
    Right _ -> return ()

  where

    translatePolicyId :: Text -> IO PolicyIdentifier
    translatePolicyId pid = do
      case readMaybe (unpack pid) of
        Just uuid -> return $ PolicyId $ PolicyUUID uuid
        Nothing -> return $ PolicyName pid

    translateUserId :: Text -> IO UserIdentifier
    translateUserId uid = do
      case readMaybe (unpack uid) of
        Just uuid ->
          return $ UserIdentifier (Just $ UserUUID uuid) Nothing Nothing
        Nothing ->
          if isValid $ encodeUtf8 uid
          then return $ UserIdentifier Nothing Nothing (Just uid)
          else return $ UserIdentifier Nothing (Just uid) Nothing


createGroupOptions :: Parser CreateGroup
createGroupOptions = CreateGroup
  <$> optional (argument str
    (  metavar "GROUP"
    <> help "The name or uuid of the group to create"
    ))
  <*> many (strOption
    ( long "policy"
    <> short 'p'
    <> metavar "POLICY"
    <> help "The ID of a policy to attach to the group"
    ))
  <*> many (strOption
    ( long "user"
    <> short 'u'
    <> metavar "USER"
    <> help "The ID of a user to add to the group"
    ))
