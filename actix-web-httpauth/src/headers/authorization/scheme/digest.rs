use crate::headers::authorization::{errors::ParseError, Scheme};
use actix_web::{
    http::header::{HeaderValue, IfNoneMatch, InvalidHeaderValue, TryIntoHeaderValue},
    web::{BufMut, Bytes, BytesMut},
};
use regex::{CaptureMatches, Regex};
use std::{
    borrow::Cow,
    collections::HashMap,
    fmt::{self, Debug},
    str,
};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Digest {
    username: Cow<'static, str>,
    realm: Cow<'static, str>,
    nonce: Cow<'static, str>,
    uri: Cow<'static, str>,
    algorithm: Cow<'static, str>,
    qop: Cow<'static, str>,
    nc: Cow<'static, str>,
    userhash: Option<Cow<'static, str>>,
    cnonce: Cow<'static, str>,
    response: Option<Cow<'static, str>>,
}

impl Scheme for Digest {
    fn parse(header: &HeaderValue) -> Result<Self, ParseError> {
        let re_digest = Regex::new(r"Digest(.+)").unwrap();
        let mut parts = re_digest
            .captures(header.to_str()?)
            .ok_or(ParseError::Invalid)
            .map(|parts| parts.get(0).unwrap().as_str())?;

        if !re_digest.is_match(header.to_str()?) {
            return Err(ParseError::MissingScheme);
        }

        //let authorization_props = Regex::new(r###"(?P<key>[a-z]+|[a-z]+\*)=(?P<prop>[[:ascii:]]+|"[[[:ascii:]][[:space]]]+"|utf8[[[:ascii::]][[:space:]]]+)"###).unwrap();

        // let authorization_props = Regex::new(r###"(?P<key>[a-z]+|[a-z]+\*)=(?P<prop>[[:ascii:]]+|"[[:ascii:]]+"|utf8[[:ascii::]]+),"###).unwrap();
        let authorization_props = Regex::new(
            r###"(?P<key>[a-z]+|[a-z]+\*)=(?P<prop>[[^,]&&[[:ascii:]]]+|"[[^,]&&[[:ascii:]]]+")"###,
        )
        .unwrap();

        let credentials = {
            let caps = authorization_props.captures_iter(parts);
            let mut credential: HashMap<&str, &str> = HashMap::new();
            for cap in caps {
                credential.insert(
                    // FIXME: Error handling
                    cap.name("key").map_or("", |m| m.as_str()),
                    cap.name("prop").map_or("", |m| m.as_str()),
                );
            }
            credential
        };

        let username = match credentials.get("username") {
            Some(username) => username.to_string().into(),
            None => credentials
                .get("username*")
                .ok_or(ParseError::MissingField("username or username*"))
                .map(|username| username.to_string().into())?,
        };

        let realm = credentials
            .get("realm")
            .ok_or(ParseError::MissingField("realm"))
            .map(|realm| realm.to_string().into())?;

        let nonce = credentials
            .get("nonce")
            .ok_or(ParseError::MissingField("nonce"))
            .map(|nonce| nonce.to_string().into())?;

        let uri = credentials
            .get("uri")
            .ok_or(ParseError::MissingField("uri"))
            .map(|uri| uri.to_string().into())?;

        let algorithm = credentials
            .get("algorithm")
            .ok_or(ParseError::MissingField("algorithm"))
            .map(|algorithm| algorithm.to_string().into())?;

        let qop: Cow<'static, str> = credentials
            .get("qop")
            .ok_or(ParseError::MissingField("qop"))
            .map(|qop| qop.to_string().into())?;

        let nc = credentials
            .get("nc")
            .ok_or(ParseError::MissingField("nc"))
            .map(|nc| nc.to_string().into())?;

        let userhash = credentials
            .get("userhash")
            .or(None)
            .map(|userhash| userhash.to_string().into());

        let cnonce = credentials
            .get("nonce")
            .ok_or(ParseError::MissingField("cnonce"))
            .map(|cnonce| cnonce.to_string().into())?;

        let response: Option<Cow<'static, str>> = match credentials.get("response") {
            Some(response) => Ok(Some(response.to_string().into())),
            None => match qop.as_ref() {
                "auth" | "auth-init" => Err(ParseError::MissingField("response")),
                _ => Ok(None),
            },
        }?;

        Ok(Self {
            username,
            realm,
            nonce,
            uri,
            algorithm,
            qop,
            nc,
            userhash,
            cnonce,
            response,
        })
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.userhash.is_none() && self.response.is_none() {
            f.write_fmt(format_args!(
                    r###"Digest username="{username}", realm="{realm}", nonce="{nonce}", uri="{uri}", algorithm={algorithm}, qop={qop}, nc={nc}, cnonce="{cnonce}""###,
                username=self.username, realm=self.realm, uri=self.uri, algorithm=self.algorithm, qop=self.qop, nc=self.nc, nonce=self.nonce, cnonce=self.cnonce))
        } else if self.userhash.is_none() {
            f.write_fmt(format_args!(
                r###"Digest username="{username}", realm="{realm}", nonce="{nonce}", uri="{uri}", algorithm={algorithm}, qop={qop}, nc={nc}, cnonce="{cnonce}", response="{response}""###,
            username=self.username, realm=self.realm, uri=self.uri, algorithm=self.algorithm, qop=self.qop, nc=self.nc, response=self.response.as_ref().unwrap(), nonce=self.nonce, cnonce=self.cnonce))
        } else if self.response.is_none() {
            f.write_fmt(format_args!(
                r###"Digest username="{username}", realm="{realm}", nonce="{nonce}", uri="{uri}", algorithm={algorithm}, qop={qop}, nc={nc}, userhash="{userhash}", cnonce="{cnonce}""###,
            username=self.username, realm=self.realm, uri=self.uri, algorithm=self.algorithm, qop=self.qop, nc=self.nc, userhash=self.userhash.as_ref().unwrap(), nonce=self.nonce, cnonce=self.cnonce))
        } else {
            f.write_fmt(format_args!(
                r###"Digest username="{username}", realm="{realm}", nonce="{nonce}", uri="{uri}", algorithm={algorithm}, qop={qop}, nc={nc}, userhash="{userhash}, cnonce="{cnonce}", response="{response}""###,
            username=self.username, realm=self.realm, uri=self.uri, algorithm=self.algorithm, qop=self.qop, nc=self.nc, userhash=self.userhash.as_ref().unwrap(), response=self.response.as_ref().unwrap(), nonce=self.nonce, cnonce=self.cnonce))
        }
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.userhash.is_none() && self.response.is_none() {
            f.write_fmt(format_args!(
                    r###"Digest username="{username}", realm="{realm}", nonce="{nonce}", uri="{uri}", algorithm={algorithm}, qop={qop}, nc={nc}, cnonce="{cnonce}""###,
                username=self.username, realm=self.realm, uri=self.uri, algorithm=self.algorithm, qop=self.qop, nc=self.nc, nonce=self.nonce, cnonce=self.cnonce))
        } else if self.userhash.is_none() {
            f.write_fmt(format_args!(
                r###"Digest username="{username}", realm="{realm}", nonce="{nonce}", uri="{uri}", algorithm={algorithm}, qop={qop}, nc={nc}, cnonce="{cnonce}", response="{response}""###,
            username=self.username, realm=self.realm, uri=self.uri, algorithm=self.algorithm, qop=self.qop, nc=self.nc, response=self.response.as_ref().unwrap(), nonce=self.nonce, cnonce=self.cnonce))
        } else if self.response.is_none() {
            f.write_fmt(format_args!(
                r###"Digest username="{username}", realm="{realm}", nonce="{nonce}", uri="{uri}", algorithm={algorithm}, qop={qop}, nc={nc}, userhash="{userhash}", cnonce="{cnonce}""###,
            username=self.username, realm=self.realm, uri=self.uri, algorithm=self.algorithm, qop=self.qop, nc=self.nc, userhash=self.userhash.as_ref().unwrap(), nonce=self.nonce, cnonce=self.cnonce))
        } else {
            f.write_fmt(format_args!(
                r###"Digest username="{username}", realm="{realm}", nonce="{nonce}", uri="{uri}", algorithm={algorithm}, qop={qop}, nc={nc}, userhash="{userhash}, cnonce="{cnonce}", response="{response}""###,
            username=self.username, realm=self.realm, uri=self.uri, algorithm=self.algorithm, qop=self.qop, nc=self.nc, userhash=self.userhash.as_ref().unwrap(), response=self.response.as_ref().unwrap(), nonce=self.nonce, cnonce=self.cnonce))
        }
    }
}

impl TryIntoHeaderValue for Digest {
    type Error = InvalidHeaderValue;

    fn try_into_value(self) -> Result<HeaderValue, Self::Error> {
        let credential = Bytes::from(format!("{:?}", self));

        HeaderValue::from_maybe_shared(credential)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_header() {
        let value = HeaderValue::from_static(
            r###"Digest username="hoge", realm="Secret Zone", nonce="RMH0usDrAwA=6dc290ea3304de42a7347e0a94089ff5912ce0de", uri="/~68user/net/sample/http-auth-digest/secret.html", algorithm=MD5, qop=auth, nc=00000001, cnonce="e78e26e0d17c978d", response="0d73182c1602ce8749feeb4b89389019""###,
        );
        let scheme = Digest::parse(&value);

        assert!(scheme.is_ok());
        let scheme = scheme.unwrap();
        assert_eq!(scheme.username, "\"hoge\"");
        assert_eq!(
            scheme.response,
            Some("\"0d73182c1602ce8749feeb4b89389019\"".into())
        );
    }

    #[test]
    fn test_empty_header() {
        let value = HeaderValue::from_static("");
        let scheme = Digest::parse(&value);

        assert!(scheme.is_err());
    }

    #[test]
    fn test_wrong_scheme() {
        let value = HeaderValue::from_static("THOUSHALLNOTPASS please?");
        let scheme = Digest::parse(&value);

        assert!(scheme.is_err());
    }

    #[test]
    fn test_missing_credentials() {
        let value = HeaderValue::from_static("Digest ");
        let scheme = Digest::parse(&value);

        assert!(scheme.is_err());
    }

    #[test]
    fn test_into_header_value() {
        let digest = Digest {
            username: "hoge".into(),
            realm: "Secret Zone".into(),
            nonce: "RMH1usDrAwA=6dc290ea3304de42a7347e0a94089ff5912ce0de".into(),
            uri: "/~68user/net/sample/http-auth-digest/secret.html".into(),
            algorithm: "MD5".into(),
            qop: "auth".into(),
            nc: "00000001".into(),
            userhash: None,
            cnonce: "e78e26e0d17c978d".into(),
            response: Some("0d73182c1602ce8749feeb4b89389019".into()),
        };

        let result = digest.try_into_value();

        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            HeaderValue::from_static(
                r###"Digest username="hoge", realm="Secret Zone", nonce="RMH1usDrAwA=6dc290ea3304de42a7347e0a94089ff5912ce0de", uri="/~68user/net/sample/http-auth-digest/secret.html", algorithm=MD5, qop=auth, nc=00000001, cnonce="e78e26e0d17c978d", response="0d73182c1602ce8749feeb4b89389019""###
            )
        );
    }
}
