# Keycloak - Custom identity provider mapper

This extension provides a _Custom Mapper_ for OpenID Connect identity provider. It is a fork of _Advanced Claim to Role Mapper_, adding capability to select claims or nested claims where path includes an array field. Result of the target key is an array of values.

```
Example :
{
  "claimA": {
    "claimsB": [
      {
        "claimC": "C1",
        "claimD": "D1"
      },
      {
        "claimC": "C2",
        "claimD": "D2"
      }
    ]
  }
}

Key = claimA.claimsB.claimC
Value = [ "C1", "D1" ]
```

Then, it allows to apply regex on result array.

## Compatibility

Version 1.0.0 is compatible with Keycloak 22.0.X.

## Install

As other [Keycloak SPI](https://www.keycloak.org/docs/latest/server_development/index.html#_implementing_spi),
* put jar file in ```/providers``` folder
* if Keycloak server il already started, stop it
* to take into account this new provider, launch following command ```/bin/kc.sh build```
* and start Keycloak server again ```/bin/kc.sh start```

## Settings

Connect to Keycloak admin console.
Select Identity Provider where you want to set up a new mapper :
![Select Identity Provider](/assets/keycloak-idp-mapper-1.jpg)
Click on **Add mapper** button and select **Custom Claim to Role** :
![Add new Identity Provider Mapper](/assets/keycloak-idp-mapper-2.jpg)
Set up your mapper config :
![Set Identity Provider Mapper Config](/assets/keycloak-idp-mapper-3.jpg)

## Development

### Build

To build your local package, execute following command ```mvnw package```

### Container

To test a provider, set version of your provider (jar file) in .env file :
```MAPPER_VERSION=1.0.0```

Then launch a Keycloak instance in a Docker container ```docker compose --env-file .env up```
