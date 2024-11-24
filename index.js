var express = require("express");
var layout = require("express-layout");
var bodyParser = require("body-parser");
var ejs = require("ejs");
var engine = require("ejs-mate");
var path = require("path");
var mysql = require("mysql");
var jwt = require("jsonwebtoken");
var LocalStorage = require("node-localstorage").LocalStorage;
const async = require("async");

var app = express();
var middleware = [layout(), express.static(path.join(__dirname, "public"))];
app.use(middleware);
app.engine("ejs", engine);
app.set("view engine", "ejs");
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const routes = require("./routes");
app.use("/", routes);

const localStorage = new LocalStorage("./scratch");

const db = mysql.createConnection({
  host: "localhost",
  port: 3306,
  user: "root",
  password: "",
  database: "shahmir",
});

db.connect((err) => {
  if (err) {
    console.error("Database connection failed:", err);
  } else {
    console.log("Connected to the database");
  }
});

function authenticateUser(email, password, callback) {
  console.log("Auth Chk");
  const query =
    "SELECT * FROM user INNER JOIN role on role_id_fk=role_id WHERE user_email = ? AND user_password = ?";

  db.query(query, [email, password], (err, results) => {
    if (err) {
      return callback(err, null);
    }

    if (results.length > 0) {
      const user = results[0];
      console.log(user.role_id_fk + " User Found " + user.role_name);
      if (user.user_status != "Active") {
        // return res.redirect("/");
        console.log("non-active user");
      }
      // Generate JWT token
      const token = jwt.sign(
        {
          user_id: user.user_id,
          username: user.user_name,
          useremail: user.user_email,
          role_id: user.role_id_fk,
          role_name: user.role_name,
        },
        "loginToken"
      );

      // Set the token in localStorage
      localStorage.setItem("userToken", token);

      callback(null, user);
    } else {
      console.log("User not found");
      callback(null, null);
    }
  });
}

app.post("/login", function (req, res) {
  const { email, password } = req.body;

  authenticateUser(email, password, (err, user) => {
    if (err) {
      return res.status(500).send("Internal Server Error1 " + err);
    }

    if (user) {
      // Access the token from localStorage
      const storedToken = localStorage.getItem("userToken");

      // Verify the token or use its data as needed
      if (storedToken) {
        try {
          const decodedToken = jwt.verify(storedToken, "loginToken");
          // Access token data, e.g., username, useremail, role_id, role_name
          const { username, useremail, role_id, role_name } = decodedToken;
          // Use the token data in your logic
          if (role_id == 1) {
            return res.redirect("/dashboard");
          } else if (role_id == 2) {
            return res.redirect("/");
          } else {
            return res.redirect("/");
          }
        } catch (error) {
          // Handle token verification error
          console.error("Token verification failed:", error.message);
          return res.redirect("/");
        }
      } else {
        // Handle case where the token is not found in localStorage
        console.error("Token not found in localStorage");
        return res.redirect("/");
      }
    } else {
      return res.redirect("/");
    }
  });
});

function extractTokenData(req, res, next) {
  // Get the token from the Authorization header
  // const token = req.headers.authorization;
  const token = localStorage.getItem("userToken");

  if (token) {
    try {
      // Verify the token
      const decodedToken = jwt.verify(token, "loginToken");

      // Attach token data to the request for later use
      req.tokenData = {
        username: decodedToken.username,
        useremail: decodedToken.useremail,
        role_id: decodedToken.role_id,
        role_name: decodedToken.role_name,
        userId: decodedToken.user_id,
      };

      // Continue with the next middleware or route handler
      next();
    } catch (error) {
      // Handle token verification error
      console.error("Token verification failed:", error.message);
      // return res.status(401).json({ error: 'Token verification failed' });
    }
  } else {
    // Token is not present in the request
    // return res.status(401).json({ error: 'Token not provided' });
  }
}

function fetchTotalRecords(userId, role_id, callback) {
  var queries = [
      "SELECT COUNT(*) as total FROM user",
      "SELECT COUNT(*) as total FROM malwaresample",
    ];
  

  const results = {};

  function executeQuery(query, tableName, callback) {
    db.query(query, [userId], (err, rows) => {
      if (err) {
        callback(err);
      } else {
        results[tableName] = rows[0].total;
        callback(null);
      }
    });
  }

  // Execute queries in parallel
  const tasks = queries.map(
    (query, index) => (cb) =>
      executeQuery(query, ["user", "malware"][index], cb)
  );

  async.parallel(tasks, (err) => {
    if (err) {
      callback(err);
    } else {
      callback(null, results);
    }
  });
}

app.get("/dashboard", extractTokenData, function (req, res) {
  const { username, useremail, role_id, role_name } = req.tokenData;
  const userId = req.params.id;
  if (role_id != 1) {
    return res.status(500).send("Only Admin Can Access This");
  }
  fetchTotalRecords(userId, role_id, (err, totals) => {
    if (err) {
      console.error("Error fetching total records:", err);
      // Handle the error (send an error response to the client)
      return res.status(500).send("Internal Server Error");
    }
    res.render("dashboard", {
      userCount: totals.user,
      malwareCount: totals.malware,
      errors: "",
      title: "VS Dashboard",
      loginUser: username,
      role_id: role_id,
      role: role_name,
    });
  });
});

app.get("/", function (req, res) {
  // const token = req.headers.authorization;
  const token = localStorage.getItem("userToken");

  if (token) {
    try {
      // Verify the token
      const decodedToken = jwt.verify(token, "loginToken");

      res.render("home", {
        input: "",
        msg: "",
        data: false,
        malware: "",
        errors: "",
        title: "VS Dashboard",
        loginUser: decodedToken.username,
        role_id: decodedToken.role_id,
        role: decodedToken.role_name,
      });

      // Continue with the next middleware or route handler
      next();
    } catch (error) {
      // Handle token verification error
      console.error("Token verification failed:", error.message);
      // return res.status(401).json({ error: 'Token verification failed' });
    }
  } else {
    res.render("home", {
      input: "",
      msg: "",
      data: false,
      errors: "",
      title: "VS Dashboard",
      loginUser: "",
      role_id: "",
      role: "",
    });
  }
});

app.get("/login", function (req, res) {
  res.render(
    "login",
    {
      errors: "",
      title: "VS Login",
      msg: "",
      loginUser: "",
    },
    function (err, html) {
      // Set layout to false to avoid using the default layout
      res.render("login", {
        content: html,
        layout: false,
        errors: "",
        title: "VS Login",
        msg: "",
      });
    }
  );
});

app.get("/signup", function (req, res) {
  res.render(
    "signup",
    {
      errors: "",
      title: "VS Signup",
      msg: "",
      loginUser: "",
    },
    function (err, html) {
      // Set layout to false to avoid using the default layout
      res.render("signup", {
        content: html,
        layout: false,
        errors: "",
        title: "VS signup",
        msg: "",
      });
    }
  );
});

app.get("/logout", function (req, res) {
  // Clear the userToken from localStorage to end the session

  const userToken = localStorage.getItem("userToken");
  if (!userToken) {
    console.log("No token");
  } else {
    const decoded = jwt.verify(userToken, "loginToken");
    console.log(decoded.username + " chk login " + decoded.role_id);
    console.log("token removed");
    localStorage.removeItem("userToken");
  }

  res.redirect("/login");
});

app.post("/", async (req, res) => {
  // const token = req.headers.authorization;
  const token = localStorage.getItem("userToken");

  var p_name = "";
  var p_role_id = "";
  var p_role_name = "";

  if (token) {
    try {
      // Verify the token
      const decodedToken = jwt.verify(token, "loginToken");

      p_name = decodedToken.username;
      p_role_id = decodedToken.role_id;
      p_role_name = decodedToken.role_name;
    } catch (error) {
      // Handle token verification error
      console.error("Token verification failed:", error.message);
      // return res.status(401).json({ error: 'Token verification failed' });
    }
  }

  const { file_hash } = req.body;

  const query = `
  SELECT
    malwaresample.*,
    incidentreport.dateTime,
    incidentreport.descriptionOfIncident,
    incidentreport.threatLevel,
    indicatorsofcompromise.ipAddress,
    indicatorsofcompromise.domainName,
    indicatorsofcompromise.url,
    indicatorsofcompromise.registryKey,
    indicatorsofcompromise.filePath,
    maliciousbehavior.behaviorDescription,
    maliciousbehavior.systemCallsOrAPIFunctions,
    maliciousbehavior.registryModifications,
    mitigationstrategy.YARARules,
    mitigationstrategy.patchInformation,
    threatactor.actorNameOrAlias,
    threatactor.motivation,
    threatactor.TTPs,
    threatactor.knownAffiliations,
    vulnerabilityexploited.vulnerabilityType,
    vulnerabilityexploited.affectedSoftwareOrSystemComponent,
    vulnerabilityexploited.CVE_ID,
    vulnerabilityexploited.patchStatus
  FROM malwaresample
  INNER JOIN incidentreport ON malwaresample.MalwareSample_id = incidentreport.MalwareSample_id_fk
  INNER JOIN indicatorsofcompromise ON malwaresample.MalwareSample_id = indicatorsofcompromise.MalwareSample_id_fk
  INNER JOIN maliciousbehavior ON malwaresample.MalwareSample_id = maliciousbehavior.MalwareSample_id_fk
  INNER JOIN mitigationstrategy ON malwaresample.MalwareSample_id = mitigationstrategy.MalwareSample_id_fk
  INNER JOIN threatactor ON malwaresample.MalwareSample_id = threatactor.MalwareSample_id_fk
  INNER JOIN vulnerabilityexploited ON malwaresample.MalwareSample_id = vulnerabilityexploited.MalwareSample_id_fk
  WHERE malwaresample.fileHash = ? AND malwaresample.status = 1`;

  db.query(query, [file_hash], (err, results) => {
    if (err) {
      console.error("Error fetching malware data:", err);
      return res.status(500).send("Internal Server Error");
    }

    const malware = results[0];
    if (malware) {
      // Records found, render with data
      res.render("home", {
        input: file_hash,
        msg: "",
        data: true,
        malware: malware,
        errors: "",
        title: "VS Home",
        loginUser: p_name,
        role_id: p_role_id,
        role: p_role_name,
      });
    } else {
      // No records found, render without data or handle as needed
      res.render("home", {
        input: "",
        msg: "No Results Found",
        data: false,
        malware: "",
        errors: "No records found",
        title: "VS Home",
        loginUser: p_name,
        role_id: p_role_id,
        role: p_role_name,
      });
    }
  });
});

app.post('/signup', (req, res) => {
  const { uname, email, password } = req.body;

  // Insert user data into the database
  const sql = 'INSERT INTO user (user_name, user_email, user_password) VALUES (?, ?, ?)';
  db.query(sql, [uname, email, password], (err, result) => {
    if (err) {
      console.error('Error inserting user data:', err);
      res.redirect('/error'); // Redirect to an error page or handle the error as needed
    } else {
      console.log('User Data Inserted:', { uname, email, password });
      res.redirect('/login');
    }
  });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
