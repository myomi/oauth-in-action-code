import * as express from "express";
import * as consolidate from "consolidate";
var url = require("url");
var bodyParser = require("body-parser");
import * as nosql from "nosql";
import * as querystring from "querystring";
import * as randomstring from "randomstring";
import { AddressInfo } from "net";
var __ = require("underscore");
__.string = require("underscore.string");
import { AuthorizeRequest, ResponseType } from "./types";

const app = express();
const db = nosql.load("database.nosql");

app.use(express.json());
app.use(express.urlencoded({extended: true}));  // support form-encoded bodies (for the token endpoint)

app.engine("html", consolidate.underscore);
app.set("view engine", "html");
app.set("views", "files/authorizationServer");
app.set("json spaces", 4);

// authorization server information
const authServer = {
  authorizationEndpoint: "http://localhost:9001/authorize",
  tokenEndpoint: "http://localhost:9001/token"
};

interface Client {
  client_id: string;
  client_secret: string;
  redirect_uris: string[];
  scope: string;
}

// client information
const clients: Client[] = [
  {
    client_id: "oauth-client-1",
    client_secret: "oauth-client-secret-1",
    redirect_uris: ["http://localhost:9000/callback"],
    scope: "foo bar"
  }
];

var codes = {};

var requests: { [key: string]: AuthorizeRequest } = {};

function getClient(clientId: string): Client {
  return clients.find(c => c.client_id === clientId);
}

/**
 * ホームページ
 */
app.get("/", (req, res) => {
  res.render("index", { clients: clients, authServer: authServer });
});

/**
 * 認可コードの発行要求
 */
app.get("/authorize", (req, res) => {
  var client = getClient(req.query.client_id);

  if (!client) {
    // 未登録のクライアントからのアクセス
    console.log("Unknown client %s", req.query.client_id);
    res.render("error", { error: "Unknown client" });
    return;
  }

  if (client.redirect_uris.findIndex(r => r === req.query.redirect_uri) < 0) {
    // 未登録のリダイレクト先が指定された
    console.log(
      "Mismatched redirect URI, expected %s got %s",
      client.redirect_uris,
      req.query.redirect_uri
    );
    res.render("error", { error: "Invalid redirect URI" });
    return;
  }

  const rscope = req.query.scope ? req.query.scope.split(" ") : undefined;
  const cscope = client.scope ? client.scope.split(" ") : undefined;
  if (__.difference(rscope, cscope).length > 0) {
    // クライアントが要求したスコープが存在しない
    const urlParsed = url.parse(req.query.redirect_uri);
    delete urlParsed.search; // this is a weird behavior of the URL library
    urlParsed.query = urlParsed.query || {};
    urlParsed.query.error = "invalid_scope";
    res.redirect(url.format(urlParsed));
    return;
  }

  // 要求されたリクエストを保存し、approve時に使用する
  const reqid = randomstring.generate(8);
  requests[reqid] = req.query;

  // リソースオーナーに確認画面を表示する
  res.render("approve", { client: client, reqid: reqid, scope: rscope });
  return;
});

/**
 * クライアントを認可 or 否認
 */
app.post("/approve", function(req, res) {
  var reqid = req.body.reqid;
  var query = requests[reqid];
  delete requests[reqid];

  if (!query) {
    // there was no matching saved request, this is an error
    res.render("error", { error: "No matching authorization request" });
    return;
  }

  if (req.body.approve) {
    if (query.response_type == "code") {
      // user approved access
      const code = randomstring.generate(8); // 認可コード

      var user = req.body.user;

      var scope = __.filter(__.keys(req.body), function(s) {
        return __.string.startsWith(s, "scope_");
      }).map(function(s) {
        return s.slice("scope_".length);
      });
      var client = getClient(query.client_id);
      var cscope = client.scope ? client.scope.split(" ") : undefined;
      if (__.difference(scope, cscope).length > 0) {
        // client asked for a scope it couldn't have
        var urlParsed = url.parse(query.redirect_uri);
        delete urlParsed.search; // this is a weird behavior of the URL library
        urlParsed.query = urlParsed.query || {};
        urlParsed.query.error = "invalid_scope";
        res.redirect(url.format(urlParsed));
        return;
      }

      // save the code and request for later
      codes[code] = {
        authorizationEndpointRequest: query,
        scope: scope,
        user: user
      };

      var urlParsed = url.parse(query.redirect_uri);
      delete urlParsed.search; // this is a weird behavior of the URL library
      urlParsed.query = urlParsed.query || {};
      urlParsed.query.code = code;
      urlParsed.query.state = query.state;
      res.redirect(url.format(urlParsed));
      return;
    } else {
      // we got a response type we don't understand
      var urlParsed = url.parse(query.redirect_uri);
      delete urlParsed.search; // this is a weird behavior of the URL library
      urlParsed.query = urlParsed.query || {};
      urlParsed.query.error = "unsupported_response_type";
      res.redirect(url.format(urlParsed));
      return;
    }
  } else {
    // user denied access
    var urlParsed = url.parse(query.redirect_uri);
    delete urlParsed.search; // this is a weird behavior of the URL library
    urlParsed.query = urlParsed.query || {};
    urlParsed.query.error = "access_denied";
    res.redirect(url.format(urlParsed));
    return;
  }
});

app.post("/token", function(req, res) {
  var auth = req.headers["authorization"];
  if (auth) {
    // check the auth header
    var clientCredentials = Buffer.from(auth.slice("basic ".length), "base64")
      .toString()
      .split(":");
    var clientId = querystring.unescape(clientCredentials[0]);
    var clientSecret = querystring.unescape(clientCredentials[1]);
  }

  // otherwise, check the post body
  if (req.body.client_id) {
    if (clientId) {
      // if we've already seen the client's credentials in the authorization header, this is an error
      console.log("Client attempted to authenticate with multiple methods");
      res.status(401).json({ error: "invalid_client" });
      return;
    }

    var clientId = req.body.client_id as string;
    var clientSecret = req.body.client_secret as string;
  }

  var client = getClient(clientId);
  if (!client) {
    console.log("Unknown client %s", clientId);
    res.status(401).json({ error: "invalid_client" });
    return;
  }

  if (client.client_secret != clientSecret) {
    console.log(
      "Mismatched client secret, expected %s got %s",
      client.client_secret,
      clientSecret
    );
    res.status(401).json({ error: "invalid_client" });
    return;
  }

  if (req.body.grant_type == "authorization_code") {
    var code = codes[req.body.code];

    if (code) {
      delete codes[req.body.code]; // burn our code, it's been used
      if (code.authorizationEndpointRequest.client_id == clientId) {
        var access_token = randomstring.generate();

        var cscope = null;
        if (code.scope) {
          cscope = code.scope.join(" ");
        }

        db.insert({
          access_token: access_token,
          client_id: clientId,
          scope: cscope
        });

        console.log("Issuing access token %s", access_token);
        console.log("with scope %s", cscope);

        var token_response = {
          access_token: access_token,
          token_type: "Bearer",
          scope: cscope
        };

        res.status(200).json(token_response);
        console.log("Issued tokens for code %s", req.body.code);

        return;
      } else {
        console.log(
          "Client mismatch, expected %s got %s",
          code.authorizationEndpointRequest.client_id,
          clientId
        );
        res.status(400).json({ error: "invalid_grant" });
        return;
      }
    } else {
      console.log("Unknown code, %s", req.body.code);
      res.status(400).json({ error: "invalid_grant" });
      return;
    }
  } else {
    console.log("Unknown grant type %s", req.body.grant_type);
    res.status(400).json({ error: "unsupported_grant_type" });
  }
});

app.use("/", express.static("files/authorizationServer"));

// clear the database on startup
db.clear();

const server = app.listen(9001, "localhost", function() {
  const address = server.address() as AddressInfo;
  console.log(
    `OAuth Authorization Server is listening at http://${address.address}:${
      address.port
    }`
  );
});
