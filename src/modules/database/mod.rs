pub mod oath_info;
pub mod profile_info;
pub mod logintoken_info;

/* oauth.db
ip TEXT PRIMARY KEY,
code TEXT,
token TEXT,
tokentype TEXT,
expiresseconds BIGINT,
expiresnanoseconds INT UNSIGNED,
refreshtoken TEXT
 */

 /* profile.db
 uuid TEXT PRIMARY KEY
 username TEXT NOT NULL
 hashed_password TEXT NOT NULL
 salt TEXT NOT NULL
  */