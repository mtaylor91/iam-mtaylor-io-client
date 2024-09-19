module IAM.Command.Login
  ( login
  , loginOptions
  , LoginOptions(..)
  ) where

import Data.Text (unpack)
import Data.UUID (toText)
import Options.Applicative

import IAM.Client hiding (login)
import IAM.Client.Util
import IAM.Config
import IAM.Session


data LoginOptions = LoginOptions deriving (Eq, Show)


login :: LoginOptions -> IO ()
login LoginOptions = do
  iamConfig <- iamClientConfigEnv
  iamClient <- newIAMClient iamConfig
  let sessionsClient = mkCallerSessionsClient
  let createSession' = IAM.Client.createSession sessionsClient
  r <- iamRequest iamClient createSession'
  case r of
    Right session ->
      let sid = toText $ unSessionId $ createSessionId session
          token = createSessionToken session
          prefix = "export " ++ envPrefix ++ "_"
       in do
        putStrLn $ prefix ++ "SESSION_ID=\"" ++ unpack sid ++ "\""
        putStrLn $ prefix ++ "SESSION_TOKEN=\"" ++ unpack token ++ "\""
    Left err ->
      handleClientError err



loginOptions :: Parser LoginOptions
loginOptions = pure LoginOptions
