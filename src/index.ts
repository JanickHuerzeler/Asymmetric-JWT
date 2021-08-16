import { KJUR as jsrsasign } from "jsrsasign";
import * as jwt from "jsonwebtoken";

const privateKey =
  "-----BEGIN RSA PRIVATE KEY-----MIICWwIBAAKBgQCEc2PBztJxzAqBJX9C5vcXqqfpuzGZR/2h2njbkqwq7fhphaQM4WadEgvNUiqbv/ZMwlYERWczyFFJRvpaWbW9x/x54DIbadVUY+0gl6/6C+oXZKKnj9rWcIhFKwzD7il4QDomWBrXxAEvq8qxMLvYe0EJFERABrg54G+FOn+vjwIDAQABAoGAVl2fmMqx8r4nw1qeBxPv3yDKaOBFUTveKOH6mMKlPUD7EGOyOyvm61jPFU0Ut4aOpjK6QAK5bsyaJHwB11RT6sHosVgcKQjH/ixlo+9e6AjaWSIX+w/rgcQM7vZs4Jf/NBWXZzwyvWqAHHTt03YUsGcS9M/YgHmSXZmmIT89S/ECQQC+rlXwHr+pY485FJrkzwXDO+q67QcFc2wLYrvP1tONFeaYYJLwh2OWORBSF9AcieQFrW+pu2pGkfhlZWgOxRojAkEAsdKVdz/QOe0xlPm1OMAbC0+YhquLSWpE3GoJ0ked8a1t/sOJoWKJjsJwDH2rOXSXQoFH52rkbU6gAugeQ869pQJAdnPGXww68/ctGcB7GHiik82827IzEmfJTqlfEpXZhWN9hFs57MGuU7vPL7ArUA84324GV+Jc+snjDNoZ8lLvEQJAKu7L9XmrvYCeGvjbHzOKlAWIruMWAwisTYcwjduKr8IOr5boUNWonpYlVW61+25B4uWxxZbSRe3Yxjriq75rnQJAKrTDeriwL2uikylA4BNaW4nOtUjBElcMRH9IFle5UPc4JVvJ5rPpXrzhPXcCZx69mr98+hSqC6v/j09XylsmRQ==-----END RSA PRIVATE KEY-----";
const publicKey =
  "-----BEGIN PUBLIC KEY-----\n" +
  "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCEc2PBztJxzAqBJX9C5vcXqqfp\n" +
  "uzGZR/2h2njbkqwq7fhphaQM4WadEgvNUiqbv/ZMwlYERWczyFFJRvpaWbW9x/x5\n" +
  "4DIbadVUY+0gl6/6C+oXZKKnj9rWcIhFKwzD7il4QDomWBrXxAEvq8qxMLvYe0EJ\n" +
  "FERABrg54G+FOn+vjwIDAQAB\n" +
  "-----END PUBLIC KEY-----";

const getSignedToken = (
  tenantId: string,
  documentId: string,
  lifetime: number = 60 * 60,
  ver: string = "1.0"
): string => {
  // Current time in seconds
  const now = Math.round(new Date().getTime() / 1000);

  const claims = {
    documentId,
    scopes: ["doc:read", "doc:write", "summary:write"],
    tenantId,
    user: {
      id: "12345",
      name: "testuser",
    },
    iat: now,
    exp: now + lifetime,
    ver,
  };

  //const utf8Key = {utf8: privateKey};
  return jsrsasign.jws.JWS.sign(
    null,
    JSON.stringify({ alg: "RS256", typ: "JWT" }),
    claims,
    privateKey
  );
};

const forgeToken = (
  _publicKey: string,
  tenantId: string,
  documentId: string,
  lifetime: number = 60 * 60,
  ver: string = "1.0"
): string => {
  // Current time in seconds
  const now = Math.round(new Date().getTime() / 1000);

  const claims = {
    documentId,
    scopes: ["doc:read", "doc:write", "summary:write"],
    tenantId,
    user: {
      id: "12345",
      name: "Forged Token User",
    },
    iat: now,
    exp: now + lifetime,
    ver,
  };

  return jsrsasign.jws.JWS.sign(
    null,
    JSON.stringify({ alg: "HS256", typ: "JWT" }),
    claims,
    _publicKey
  );
};

const verifySignedToken = (
  _token: string,
  _publicKey: string
): Promise<jwt.JwtPayload> => {
  return new Promise((resolve, reject) => {
    jwt.verify(_token, _publicKey, (error, decodedPayload) => {
      if (error) {
        reject(error);
      } else {
        resolve(decodedPayload);
      }
    });
  });
};

(async () => {
  const token = getSignedToken(
    "Routerlicious-Asymmetric-Tenant-Experiment",
    "tags_TEXT_refactored_022"
  );
  console.log("token:", token);

  try {
    const verifiedPayload = await verifySignedToken(token, publicKey);
    console.log("verifiedPayload:", verifiedPayload);
  } catch (e) {
    console.error("Could not verify token:", e);
  }

  const forgedToken = forgeToken(
    publicKey,
    "Routerlicious-Asymmetric-Tenant-Experiment",
    "tags_TEXT_refactored_022"
  );

  console.log("forgedToken:", forgedToken);

  try {
    const verifiedForgedToken = verifySignedToken(forgedToken, publicKey);
    console.log("verifiedForgedTokenPayload:", verifiedForgedToken);
  } catch (e) {
    console.error("Could not verify forged token:", e);
  }
})();
