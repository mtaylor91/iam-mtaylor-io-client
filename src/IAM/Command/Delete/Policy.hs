module IAM.Command.Delete.Policy
  ( deletePolicy
  , deletePolicyOptions
  , DeletePolicy(..)
  ) where

import Data.Text
import Data.UUID
import Options.Applicative
import Text.Read

import IAM.Client.Util
import IAM.Policy
import qualified IAM.Client


newtype DeletePolicy = DeletePolicy
  { deletePolicyPolicyId :: Text
  } deriving (Show)


deletePolicy :: DeletePolicy -> IO ()
deletePolicy deletePolicyInfo = do
  case readMaybe (unpack $ deletePolicyPolicyId deletePolicyInfo) of
    Just uuid -> deletePolicyByUUID uuid
    Nothing -> deletePolicyByName $ deletePolicyPolicyId deletePolicyInfo


deletePolicyByName :: Text -> IO ()
deletePolicyByName polName = deletePolicyByIdentifier $ PolicyName polName


deletePolicyByUUID :: UUID -> IO ()
deletePolicyByUUID polId = deletePolicyByIdentifier $ PolicyId $ PolicyUUID polId


deletePolicyByIdentifier :: PolicyIdentifier -> IO ()
deletePolicyByIdentifier polId = do
  iamConfig <- IAM.Client.iamClientConfigEnv
  iamClient <- IAM.Client.newIAMClient iamConfig

  let polClient = IAM.Client.mkPolicyClient polId
  res <- IAM.Client.iamRequest iamClient $ IAM.Client.deletePolicy polClient
  case res of
    Left err -> handleClientError err
    Right _ -> return ()


deletePolicyOptions :: Parser DeletePolicy
deletePolicyOptions = DeletePolicy
  <$> argument str
      ( metavar "POLICY_ID"
     <> help "The uuid of the policy to delete."
      )
