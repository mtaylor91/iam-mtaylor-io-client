module IAM.Command.Get.Policy
  ( IAM.Command.Get.Policy.getPolicy
  ) where

import Data.Aeson
import Data.ByteString.Lazy (toStrict)
import Data.Text.Encoding
import Data.UUID
import Text.Read
import qualified Data.Text as T

import IAM.Client
import IAM.Client.Util
import IAM.Policy


getPolicy :: T.Text -> IO ()
getPolicy identifier = case readMaybe (T.unpack identifier) of
  Just uuid -> getPolicyByUUID uuid
  Nothing -> getPolicyByName identifier


getPolicyByUUID :: UUID -> IO ()
getPolicyByUUID uuid = getPolicyByIdentifier $ PolicyId $ PolicyUUID uuid


getPolicyByName :: T.Text -> IO ()
getPolicyByName = getPolicyByIdentifier . PolicyName


getPolicyByIdentifier :: PolicyIdentifier -> IO ()
getPolicyByIdentifier identifier = do
  iamConfig <- iamClientConfigEnv
  iamClient <- newIAMClient iamConfig
  let policyClient = mkPolicyClient identifier
  result <- iamRequest iamClient $ IAM.Client.getPolicy policyClient
  case result of
    Right policy' ->
      putStrLn $ T.unpack (decodeUtf8 $ toStrict $ encode $ toJSON policy')
    Left err ->
      handleClientError err
