module IAM.Command.Logout
  ( logout
  , logoutOptions
  , LogoutOptions(..)
  ) where

import Options.Applicative

import IAM.Client
import IAM.Client.Util
import IAM.Config


data LogoutOptions = LogoutOptions deriving (Eq, Show)


logout :: LogoutOptions -> IO ()
logout LogoutOptions = do
  iamConfig <- iamClientConfigEnv
  iamClient <- newIAMClient iamConfig
  sid <- configSessionId
  let sessionsClient = mkCallerSessionsClient
  let sessionClient' = userSessionClient sessionsClient sid
  let deleteSession' = deleteUserSession sessionClient'
  r <- iamRequest iamClient deleteSession'
  case r of
    Left err -> handleClientError err
    Right _ -> do
      let prefix = "unset " ++ envPrefix ++ "_"
      putStrLn $ prefix ++ "SESSION_ID"
      putStrLn $ prefix ++ "SESSION_TOKEN"


logoutOptions :: Parser LogoutOptions
logoutOptions = pure LogoutOptions
