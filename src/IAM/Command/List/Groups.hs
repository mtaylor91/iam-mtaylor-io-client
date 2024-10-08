module IAM.Command.List.Groups
  ( listGroups
  , listGroupsOptions
  , ListGroupsOptions(..)
  ) where

import Data.Aeson (encode, toJSON)
import Data.ByteString.Lazy (toStrict)
import Data.Text as T
import Data.Text.Encoding
import Options.Applicative

import IAM.Client.Util
import IAM.Sort
import qualified IAM.Client


data ListGroupsOptions = ListGroupsOptions
  { listGroupsSearch :: Maybe Text
  , listGroupsOffset :: Maybe Int
  , listGroupsLimit :: Maybe Int
  } deriving (Show)


listGroups :: ListGroupsOptions -> IO ()
listGroups opts = do
  let mSort = Nothing
  let mOrder = Nothing
  listGroups' opts mSort mOrder


listGroups' :: ListGroupsOptions -> Maybe SortGroupsBy -> Maybe SortOrder -> IO ()
listGroups' opts mSort mOrder = do
  let search = listGroupsSearch opts
  let offset = listGroupsOffset opts
  let limit = listGroupsLimit opts
  iamConfig <- IAM.Client.iamClientConfigEnv
  iamClient <- IAM.Client.newIAMClient iamConfig
  let clientOp = IAM.Client.listGroups search mSort mOrder offset limit
  result <- IAM.Client.iamRequest iamClient clientOp
  case result of
    Right groups ->
      putStrLn $ T.unpack (decodeUtf8 $ toStrict $ encode $ toJSON groups)
    Left err ->
      handleClientError err


listGroupsOptions :: Parser ListGroupsOptions
listGroupsOptions = ListGroupsOptions
  <$> optional (strOption
    ( long "search"
    <> short 's'
    <> metavar "SEARCH"
    <> help "Search term for filtering groups" ))
  <*> optional (option auto
    ( long "offset"
    <> short 'o'
    <> metavar "OFFSET"
    <> help "Offset for pagination" ))
  <*> optional (option auto
    ( long "limit"
    <> short 'l'
    <> metavar "LIMIT"
    <> help "Limit for pagination" ))
