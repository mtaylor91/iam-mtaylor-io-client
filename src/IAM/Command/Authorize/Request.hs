module IAM.Command.Authorize.Request
  ( authorizeRequest
  , authorizeRequestCommand
  , AuthorizeRequestCommand(..)
  ) where

import Data.Text
import Data.Text.Encoding
import Options.Applicative
import Text.Email.Validate
import Text.Read

import IAM.Authentication
import IAM.Authorization
import IAM.Client.Util
import IAM.UserIdentifier
import qualified IAM.Client


data AuthorizeRequestCommand = AuthorizeRequestCommand
  { authorizeUser :: !Text
  , authorizeHost :: !Text
  , authorizeMethod :: !Text
  , authorizeResource :: !Text
  , authorizeToken :: !(Maybe Text)
  } deriving (Show)


authorizeRequest :: AuthorizeRequestCommand -> IO ()
authorizeRequest cmd = do
  iamConfig <- IAM.Client.iamClientConfigEnv
  iamClient <- IAM.Client.newIAMClient iamConfig

  reqUser <- case readMaybe (unpack $ authorizeUser cmd) of
    Just uuid ->
      return $ UserIdentifier (Just $ UserUUID uuid) Nothing Nothing
    Nothing ->
      if isValid $ encodeUtf8 $ authorizeUser cmd
      then return $ UserIdentifier Nothing Nothing (Just $ authorizeUser cmd)
      else return $ UserIdentifier Nothing (Just $ authorizeUser cmd) Nothing

  let reqMethod = encodeUtf8 $ authorizeMethod cmd
  let reqAction = actionFromMethod reqMethod
  let req = AuthorizationRequest
        { authorizationRequestUser = reqUser
        , authorizationRequestAction = reqAction
        , authorizationRequestResource = authorizeResource cmd
        , authorizationRequestHost = authorizeHost cmd
        , authorizationRequestToken = authorizeToken cmd
        }

  let authorizeClient = IAM.Client.authorizeClient req
  r <- IAM.Client.iamRequest iamClient authorizeClient
  case r of
    Right (AuthorizationResponse decision) ->
      print decision
    Left err ->
      handleClientError err


authorizeRequestCommand :: Parser AuthorizeRequestCommand
authorizeRequestCommand = AuthorizeRequestCommand
  <$> argument str
      ( metavar "USER"
     <> help "User to authorize"
      )
  <*> argument str
      ( metavar "HOST"
      <> help "Host to authorize"
      )
  <*> argument str
      ( metavar "METHOD"
     <> help "Method to authorize"
      )
  <*> argument str
      ( metavar "RESOURCE"
     <> help "Resource to authorize"
      )
  <*> optional (strOption
      ( long "token"
      <> short 't'
      <> metavar "TOKEN"
      <> help "Token to use for authorization"
      ))
