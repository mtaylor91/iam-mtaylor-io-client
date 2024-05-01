{-# LANGUAGE OverloadedStrings #-}
module IAM.Command ( options, run ) where

import Options.Applicative

import IAM.Command.Authorize
import IAM.Command.Create
import IAM.Command.Delete
import IAM.Command.Get
import IAM.Command.List
import IAM.Command.Login
import IAM.Command.Logout
import IAM.Command.Keypair


data Command
  = Authorize !AuthorizeCommand
  | Create !CreateCommand
  | Delete !DeleteCommand
  | Get !GetCommand
  | List !ListCommand
  | Login !LoginOptions
  | Logout !LogoutOptions
  | Keypair !KeypairOptions
  deriving (Show)


newtype Options = Options Command deriving (Show)


options :: Parser Options
options = Options <$> hsubparser
  ( command "authorize"
    (info (Authorize <$> authorizeCommand)
    (progDesc "Authorize a user to perform an action"))
  <> command "create"
    (info (Create <$> createCommand) (progDesc "Create resources"))
  <> command "delete"
    (info (Delete <$> deleteCommand) (progDesc "Delete resources"))
  <> command "get"
    (info (Get <$> getCommand) (progDesc "Get resources"))
  <> command "list"
    (info (List <$> listCommand) (progDesc "List resources"))
  <> command "login"
    (info (Login <$> loginOptions) (progDesc "Login to the service"))
  <> command "logout"
    (info (Logout <$> logoutOptions) (progDesc "Logout of the service"))
  <> command "keypair"
    (info (Keypair <$> keypairOptions) (progDesc "Generate a keypair"))
  )


runOptions :: Options -> IO ()
runOptions opts =
  case opts of
    Options (Authorize cmd) ->
      authorize cmd
    Options (Create cmd) ->
      create cmd
    Options (Delete cmd) ->
      delete cmd
    Options (Get cmd) ->
      get cmd
    Options (List cmd) ->
      list cmd
    Options (Login opts') ->
      login opts'
    Options (Logout opts') ->
      logout opts'
    Options (Keypair opts') ->
      keypair opts'


run :: IO ()
run = execParser opts >>= runOptions
  where
    opts = info (options <**> helper)
      ( fullDesc
     <> header "iam-mtaylor-io - CLI for iam.mtaylor.io."
      )
