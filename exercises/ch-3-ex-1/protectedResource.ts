import * as express from "express";
import { Request, Response, NextFunction } from "express";
import * as consolidate from "consolidate";
import { AddressInfo } from "net";
var bodyParser = require("body-parser");
import * as nosql from "nosql";
var cors = require("cors");

const app = express();

app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for bearer tokens)

app.engine("html", consolidate.underscore);
app.set("view engine", "html");
app.set("views", "files/protectedResource");
app.set("json spaces", 4);

app.use("/", express.static("files/protectedResource"));
app.use(cors());

const resource = {
  name: "Protected Resource",
  description: "This data has been protected by OAuth 2.0"
};

var getAccessToken = function(req: Request, res: Response, next: NextFunction) {
  // check the auth header first
  var auth = req.headers["authorization"];
  var inToken = null;
  if (auth && auth.toLowerCase().indexOf("bearer") == 0) {
    inToken = auth.slice("bearer ".length);
  } else if (req.body && req.body.access_token) {
    // not in the header, check in the form body
    inToken = req.body.access_token;
  } else if (req.query && req.query.access_token) {
    inToken = req.query.access_token;
  }

  console.log("Incoming token: %s", inToken);
  const db = nosql.load("database.nosql");
  db.find().make(filter => {
    filter.where("access_token", inToken);
    filter.callback((err, response) => {
      if (err) {
		console.log("No matching token was found.");
      } else {
        console.log("We found a matching token: %s", inToken);
        (req as any).access_token = response;
        next();
      }
    });
  });
};

app.options("/resource", cors());
app.post("/resource", cors(), getAccessToken, function(req, res) {
  if ((req as any).access_token) {
    res.json(resource);
  } else {
    res.status(401).end();
  }
});

var server = app.listen(9002, "localhost", function() {
  const address = server.address() as AddressInfo;
  console.log(
    `OAuth Resource Server is listening at http://${address.address}:${
      address.port
    }`
  );
});
