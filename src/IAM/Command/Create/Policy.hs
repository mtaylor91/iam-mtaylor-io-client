{-# LANGUAGE OverloadedStrings #-}
module IAM.Command.Create.Policy
  ( createPolicy
  , createPolicyOptions
  , CreatePolicy(..)
  ) where

import Control.Exception
import Data.Text as T
import Data.UUID
import Data.UUID.V4
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Options.Applicative
import Servant.Client
import Text.Read

import IAM.Client.Auth
import IAM.Client.Util
import IAM.Policy
import qualified IAM.Client


data CreatePolicy
  = CreatePolicy
    { createPolicyHost :: !Text
    , createPolicyUUID :: !(Maybe Text)
    , createPolicyName :: !(Maybe Text)
    , createPolicyAllowRead :: ![Text]
    , createPolicyAllowWrite :: ![Text]
    , createPolicyDenyRead :: ![Text]
    , createPolicyDenyWrite :: ![Text]
    } deriving (Show)


createPolicy :: CreatePolicy -> IO ()
createPolicy createPolicyInfo =
  case createPolicyUUID createPolicyInfo of
    Nothing -> nextRandom >>= createPolicyWithUUID createPolicyInfo
    Just uuid -> case readMaybe $ unpack uuid of
      Just uuid' -> createPolicyWithUUID createPolicyInfo uuid'
      Nothing -> throw $ userError "Invalid UUID"


createPolicyWithUUID :: CreatePolicy -> UUID -> IO ()
createPolicyWithUUID createPolicyInfo uuid =
  createPolicy' $ Policy (PolicyUUID uuid) maybeName host' stmts
  where
  maybeName = createPolicyName createPolicyInfo
  host' = createPolicyHost createPolicyInfo
  stmts = allowStmts ++ denyStmts
  allowStmts = allowReadStmts ++ allowWriteStmts
  allowReadStmts = Rule Allow Read <$> createPolicyAllowRead createPolicyInfo
  allowWriteStmts = Rule Allow Write <$> createPolicyAllowWrite createPolicyInfo
  denyStmts = denyReadStmts ++ denyWriteStmts
  denyReadStmts = Rule Deny Read <$> createPolicyDenyRead createPolicyInfo
  denyWriteStmts = Rule Deny Write <$> createPolicyDenyWrite createPolicyInfo


createPolicy' :: Policy -> IO ()
createPolicy' policy = do
  url <- serverUrl
  auth <- clientAuthInfo
  mgr <- newManager tlsManagerSettings { managerModifyRequest = clientAuth auth }
  result <- runClientM (IAM.Client.createPolicy policy) $ mkClientEnv mgr url
  case result of
    Right _ ->
      putStrLn $ unpack $ toText $ unPolicyId $ policyId policy
    Left err ->
      handleClientError err


createPolicyOptions :: Parser CreatePolicy
createPolicyOptions = CreatePolicy
  <$> argument str
      ( metavar "HOST"
     <> help "Service hostname"
      )
  <*> optional (argument str
      ( metavar "UUID"
     <> help "Policy UUID"
      ))
  <*> optional (strOption
      ( long "name"
     <> metavar "NAME"
     <> help "Policy name"
      ))
  <*> many (strOption
      ( long "allow-read"
     <> metavar "RESOURCE"
     <> help "Allow read access to resource"
      ))
  <*> many (strOption
      ( long "allow-write"
     <> metavar "RESOURCE"
     <> help "Allow write access to resource"
      ))
  <*> many (strOption
      ( long "deny-read"
     <> metavar "RESOURCE"
     <> help "Deny read access to resource"
      ))
  <*> many (strOption
      ( long "deny-write"
     <> metavar "RESOURCE"
     <> help "Deny write access to resource"
      ))
