--
-- Table structure for table `openid_assoc`
--

DROP TABLE IF EXISTS `openid_assoc`;
CREATE TABLE `openid_assoc` (
  `serial` bigint(20) unsigned NOT NULL auto_increment,
  `assoc_type` char(20) collate utf8_bin NOT NULL,
  `session_type` char(20) collate utf8_bin NOT NULL,
  `mac_key` varchar(128) collate utf8_bin NOT NULL,
  `timestamp` bigint(20) unsigned NOT NULL,
  PRIMARY KEY  (`serial`)
) ENGINE=MyISAM AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

--
-- Table structure for table `openid_users`
--

DROP TABLE IF EXISTS `openid_users`;
CREATE TABLE `openid_users` (
  `serial` bigint(20) NOT NULL auto_increment,
  `username` varchar(255) collate utf8_bin NOT NULL,
  `password` char(40) collate utf8_bin NOT NULL,
  `user_key` char(40) collate utf8_bin NOT NULL,
  `key_expires` bigint(20) NOT NULL,
  `name` varchar(128) collate utf8_bin default NULL,
  `homepage` varchar(255) collate utf8_bin default NULL,
  PRIMARY KEY  (`serial`),
  UNIQUE KEY `username` (`username`)
) ENGINE=MyISAM AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

--
-- Table structure for table `openid_sigs`
--

DROP TABLE IF EXISTS `openid_sigs`;
CREATE TABLE `openid_sigs` (
  `serial` bigint(20) unsigned NOT NULL auto_increment,
  `assoc_handle` bigint(20) unsigned NOT NULL,
  `nonce` varchar(128) collate utf8_bin NOT NULL,
  `signed` varchar(128) collate utf8_bin NOT NULL,
  `signature` varchar(128) collate utf8_bin NOT NULL,
  `identity` varchar(512) collate utf8_bin NOT NULL,
  `realm` varchar(512) collate utf8_bin NOT NULL,
  `timestamp` bigint(20) unsigned NOT NULL,
  `stat` char(1) collate utf8_bin NOT NULL,
  PRIMARY KEY  (`serial`),
  UNIQUE KEY `handle_nonce` (`assoc_handle`,`nonce`)
) ENGINE=MyISAM AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

--
-- Table structure for table `nonce`
--

DROP TABLE IF EXISTS `nonce`;
CREATE TABLE `nonce` (
  `serial` bigint(20) unsigned NOT NULL auto_increment,
  `random` bigint(20) unsigned NOT NULL,
  `timestamp` bigint(20) unsigned NOT NULL,
  PRIMARY KEY  (`serial`)
) ENGINE=MyISAM AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

