# Work in progress
It's not ready yet, work in progress.
No examples yet as well.

# Rocho
Rocho is authentication framework for golang.

It consists of main two parts:
1. Called per request - Session part(managed with `rocho.SessionEngine`) - responsible for getting `rocho.AuthToken` from request and validating/filling with it additonal data, like user details fetched from database 
2. Called per login - Authentication part(managed with `rocho.AuthEngine`) - responsible for getting `rocho.AuthData`, parsing it, getting user info(with `rocho.UserDataProvider`) and authenticating user with `rocho.Authenticator` and issuing `rocho.AuthToken` and serializing it to response.