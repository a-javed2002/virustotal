-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Nov 24, 2024 at 02:48 PM
-- Server version: 10.4.28-MariaDB
-- PHP Version: 8.1.17

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `shahmir`
--

-- --------------------------------------------------------

--
-- Table structure for table `incidentreport`
--

CREATE TABLE `incidentreport` (
  `IncidentReport_id` int(11) NOT NULL,
  `MalwareSample_id_fk` int(11) NOT NULL,
  `dateTime` datetime NOT NULL,
  `descriptionOfIncident` text DEFAULT NULL,
  `threatLevel` varchar(50) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `incidentreport`
--

INSERT INTO `incidentreport` (`IncidentReport_id`, `MalwareSample_id_fk`, `dateTime`, `descriptionOfIncident`, `threatLevel`) VALUES
(1, 1, '2024-11-24 00:00:00', 'test', 'test');

-- --------------------------------------------------------

--
-- Table structure for table `indicatorsofcompromise`
--

CREATE TABLE `indicatorsofcompromise` (
  `IoC_id` int(11) NOT NULL,
  `MalwareSample_id_fk` int(11) NOT NULL,
  `ipAddress` varchar(255) DEFAULT NULL,
  `domainName` varchar(255) DEFAULT NULL,
  `url` varchar(255) DEFAULT NULL,
  `registryKey` varchar(255) DEFAULT NULL,
  `filePath` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `indicatorsofcompromise`
--

INSERT INTO `indicatorsofcompromise` (`IoC_id`, `MalwareSample_id_fk`, `ipAddress`, `domainName`, `url`, `registryKey`, `filePath`) VALUES
(1, 1, 'test', 'test', 'test', 'test', 'test');

-- --------------------------------------------------------

--
-- Table structure for table `maliciousbehavior`
--

CREATE TABLE `maliciousbehavior` (
  `MaliciousBehavior_id` int(11) NOT NULL,
  `MalwareSample_id_fk` int(11) NOT NULL,
  `behaviorDescription` text DEFAULT NULL,
  `systemCallsOrAPIFunctions` text DEFAULT NULL,
  `registryModifications` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `maliciousbehavior`
--

INSERT INTO `maliciousbehavior` (`MaliciousBehavior_id`, `MalwareSample_id_fk`, `behaviorDescription`, `systemCallsOrAPIFunctions`, `registryModifications`) VALUES
(1, 1, 'test', 'test', 'test');

-- --------------------------------------------------------

--
-- Table structure for table `malwaresample`
--

CREATE TABLE `malwaresample` (
  `MalwareSample_id` int(11) NOT NULL,
  `fileHash` varchar(255) NOT NULL,
  `status` int(11) DEFAULT 1,
  `fileSize` varchar(100) NOT NULL,
  `fileType` varchar(100) NOT NULL,
  `malwareCategory` varchar(100) NOT NULL,
  `user_id_fk` int(11) NOT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `malwaresample`
--

INSERT INTO `malwaresample` (`MalwareSample_id`, `fileHash`, `status`, `fileSize`, `fileType`, `malwareCategory`, `user_id_fk`, `created_at`, `updated_at`) VALUES
(1, 'sample', 1, '12', 'jkl', 'idk', 1, '2024-11-24 13:45:16', '2024-11-24 13:45:22');

-- --------------------------------------------------------

--
-- Table structure for table `mitigationstrategy`
--

CREATE TABLE `mitigationstrategy` (
  `MitigationStrategy_id` int(11) NOT NULL,
  `MalwareSample_id_fk` int(11) NOT NULL,
  `YARARules` text DEFAULT NULL,
  `patchInformation` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `mitigationstrategy`
--

INSERT INTO `mitigationstrategy` (`MitigationStrategy_id`, `MalwareSample_id_fk`, `YARARules`, `patchInformation`) VALUES
(1, 1, 'test', 'test');

-- --------------------------------------------------------

--
-- Table structure for table `role`
--

CREATE TABLE `role` (
  `role_id` int(11) NOT NULL,
  `role_name` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `role`
--

INSERT INTO `role` (`role_id`, `role_name`) VALUES
(1, 'admin'),
(2, 'user');

-- --------------------------------------------------------

--
-- Table structure for table `threatactor`
--

CREATE TABLE `threatactor` (
  `ThreatActor_id` int(11) NOT NULL,
  `MalwareSample_id_fk` int(11) NOT NULL,
  `actorNameOrAlias` varchar(255) DEFAULT NULL,
  `motivation` varchar(255) DEFAULT NULL,
  `TTPs` text DEFAULT NULL,
  `knownAffiliations` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `threatactor`
--

INSERT INTO `threatactor` (`ThreatActor_id`, `MalwareSample_id_fk`, `actorNameOrAlias`, `motivation`, `TTPs`, `knownAffiliations`) VALUES
(1, 1, 'test', 'test', 'test', 'test');

-- --------------------------------------------------------

--
-- Table structure for table `user`
--

CREATE TABLE `user` (
  `user_id` int(11) NOT NULL,
  `user_name` varchar(255) NOT NULL,
  `user_email` varchar(255) NOT NULL,
  `user_password` varchar(255) NOT NULL,
  `role_id_fk` int(11) DEFAULT NULL,
  `user_status` varchar(50) DEFAULT 'Active'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `user`
--

INSERT INTO `user` (`user_id`, `user_name`, `user_email`, `user_password`, `role_id_fk`, `user_status`) VALUES
(1, 'abdullah', 'a.javed0202@gmail.com', '123', 1, 'Active');

-- --------------------------------------------------------

--
-- Table structure for table `vulnerabilityexploited`
--

CREATE TABLE `vulnerabilityexploited` (
  `VulnerabilityExploited_id` int(11) NOT NULL,
  `MalwareSample_id_fk` int(11) NOT NULL,
  `vulnerabilityType` varchar(255) DEFAULT NULL,
  `affectedSoftwareOrSystemComponent` varchar(255) DEFAULT NULL,
  `CVE_ID` varchar(50) DEFAULT NULL,
  `patchStatus` varchar(50) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `vulnerabilityexploited`
--

INSERT INTO `vulnerabilityexploited` (`VulnerabilityExploited_id`, `MalwareSample_id_fk`, `vulnerabilityType`, `affectedSoftwareOrSystemComponent`, `CVE_ID`, `patchStatus`) VALUES
(1, 1, 'test', 'test', 'test', 'test');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `incidentreport`
--
ALTER TABLE `incidentreport`
  ADD PRIMARY KEY (`IncidentReport_id`),
  ADD KEY `MalwareSample_id_fk` (`MalwareSample_id_fk`);

--
-- Indexes for table `indicatorsofcompromise`
--
ALTER TABLE `indicatorsofcompromise`
  ADD PRIMARY KEY (`IoC_id`),
  ADD KEY `MalwareSample_id_fk` (`MalwareSample_id_fk`);

--
-- Indexes for table `maliciousbehavior`
--
ALTER TABLE `maliciousbehavior`
  ADD PRIMARY KEY (`MaliciousBehavior_id`),
  ADD KEY `MalwareSample_id_fk` (`MalwareSample_id_fk`);

--
-- Indexes for table `malwaresample`
--
ALTER TABLE `malwaresample`
  ADD PRIMARY KEY (`MalwareSample_id`),
  ADD UNIQUE KEY `fileHash` (`fileHash`);

--
-- Indexes for table `mitigationstrategy`
--
ALTER TABLE `mitigationstrategy`
  ADD PRIMARY KEY (`MitigationStrategy_id`),
  ADD KEY `MalwareSample_id_fk` (`MalwareSample_id_fk`);

--
-- Indexes for table `role`
--
ALTER TABLE `role`
  ADD PRIMARY KEY (`role_id`);

--
-- Indexes for table `threatactor`
--
ALTER TABLE `threatactor`
  ADD PRIMARY KEY (`ThreatActor_id`),
  ADD KEY `MalwareSample_id_fk` (`MalwareSample_id_fk`);

--
-- Indexes for table `user`
--
ALTER TABLE `user`
  ADD PRIMARY KEY (`user_id`),
  ADD UNIQUE KEY `user_email` (`user_email`);

--
-- Indexes for table `vulnerabilityexploited`
--
ALTER TABLE `vulnerabilityexploited`
  ADD PRIMARY KEY (`VulnerabilityExploited_id`),
  ADD KEY `MalwareSample_id_fk` (`MalwareSample_id_fk`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `incidentreport`
--
ALTER TABLE `incidentreport`
  MODIFY `IncidentReport_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `indicatorsofcompromise`
--
ALTER TABLE `indicatorsofcompromise`
  MODIFY `IoC_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `maliciousbehavior`
--
ALTER TABLE `maliciousbehavior`
  MODIFY `MaliciousBehavior_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `malwaresample`
--
ALTER TABLE `malwaresample`
  MODIFY `MalwareSample_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `mitigationstrategy`
--
ALTER TABLE `mitigationstrategy`
  MODIFY `MitigationStrategy_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `role`
--
ALTER TABLE `role`
  MODIFY `role_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT for table `threatactor`
--
ALTER TABLE `threatactor`
  MODIFY `ThreatActor_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `user`
--
ALTER TABLE `user`
  MODIFY `user_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT for table `vulnerabilityexploited`
--
ALTER TABLE `vulnerabilityexploited`
  MODIFY `VulnerabilityExploited_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `incidentreport`
--
ALTER TABLE `incidentreport`
  ADD CONSTRAINT `incidentreport_ibfk_1` FOREIGN KEY (`MalwareSample_id_fk`) REFERENCES `malwaresample` (`MalwareSample_id`);

--
-- Constraints for table `indicatorsofcompromise`
--
ALTER TABLE `indicatorsofcompromise`
  ADD CONSTRAINT `indicatorsofcompromise_ibfk_1` FOREIGN KEY (`MalwareSample_id_fk`) REFERENCES `malwaresample` (`MalwareSample_id`);

--
-- Constraints for table `maliciousbehavior`
--
ALTER TABLE `maliciousbehavior`
  ADD CONSTRAINT `maliciousbehavior_ibfk_1` FOREIGN KEY (`MalwareSample_id_fk`) REFERENCES `malwaresample` (`MalwareSample_id`);

--
-- Constraints for table `mitigationstrategy`
--
ALTER TABLE `mitigationstrategy`
  ADD CONSTRAINT `mitigationstrategy_ibfk_1` FOREIGN KEY (`MalwareSample_id_fk`) REFERENCES `malwaresample` (`MalwareSample_id`);

--
-- Constraints for table `threatactor`
--
ALTER TABLE `threatactor`
  ADD CONSTRAINT `threatactor_ibfk_1` FOREIGN KEY (`MalwareSample_id_fk`) REFERENCES `malwaresample` (`MalwareSample_id`);

--
-- Constraints for table `vulnerabilityexploited`
--
ALTER TABLE `vulnerabilityexploited`
  ADD CONSTRAINT `vulnerabilityexploited_ibfk_1` FOREIGN KEY (`MalwareSample_id_fk`) REFERENCES `malwaresample` (`MalwareSample_id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
