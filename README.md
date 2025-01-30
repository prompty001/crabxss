## CrabXss

Written in Rust, this tool analyzes an URL ou a list of it and, combined with Tonomnom's tool [qsreplace](https://github.com/tomnomnom/qsreplace), sends multiple requests, then checks if the payload provided by the user was reflected in the response, leading to possible XSS.
