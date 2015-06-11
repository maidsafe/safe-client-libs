# maidsafe_client

**Primary Maintainer:**     Spandan Sharma (spandan.sharma@maidsafe.net)

**Secondary Maintainer:**   Krishna Kumar (krishna.kumar@maidsafe.net)

|Crate|Linux|Windows|OSX|Coverage|
|:------:|:-------:|:-------:|:-------:|:-------:|
|[![](http://meritbadge.herokuapp.com/maidsafe_client)](https://crates.io/crates/maidsafe_client)|[![Build Status](https://travis-ci.org/maidsafe/maidsafe_client.svg?branch=master)](https://travis-ci.org/maidsafe/maidsafe_client)|[![Build Status](http://ci.maidsafe.net:8080/buildStatus/icon?job=maidsafe_client_win64_status_badge)](http://ci.maidsafe.net:8080/job/maidsafe_client_win64_status_badge/)|[![Build Status](http://ci.maidsafe.net:8080/buildStatus/icon?job=maidsafe_client_osx_status_badge)](http://ci.maidsafe.net:8080/job/maidsafe_client_osx_status_badge/)|[![Coverage Status](https://coveralls.io/repos/maidsafe/maidsafe_client/badge.svg?branch=master)](https://coveralls.io/r/maidsafe/maidsafe_client?branch=master)|

| [API Documentation](http://maidsafe.github.io/maidsafe_client/)| [SAFENetwork System Documention](http://systemdocs.maidsafe.net/) | [MaidSafe website](http://www.maidsafe.net) | [Safe Community site](https://forum.safenetwork.io) |

#Todo
- [X] [MAID-1077](https://maidsafe.atlassian.net/browse/MAID-1077) Account Creation
    - [X] [MAID-1078](https://maidsafe.atlassian.net/browse/MAID-1078) Register
    - [X] [MAID-1079](https://maidsafe.atlassian.net/browse/MAID-1079) Login
- [X] Implement Storage API
    - [X] [MAID-1080](https://maidsafe.atlassian.net/browse/MAID-1080) Implement types
        - [X] Implement MetaData, File and DirectoryListing types
        - [X] Implement wrapper traits
    - [X] Implement Helpers
        - [X] [MAID-1081](https://maidsafe.atlassian.net/browse/MAID-1081) Directory Helper
            - [X] Save DirectoryListing
            - [X] Get Directory
            - [X] Get Directory Versions
        - [X] File Helper
            - [X] [MAID-1082](https://maidsafe.atlassian.net/browse/MAID-1082) Create File, update file and Metatdata
            - [X] [MAID-1083](https://maidsafe.atlassian.net/browse/MAID-1083) Get Versions
            - [X] [MAID-1084](https://maidsafe.atlassian.net/browse/MAID-1084) Read File
        - [X] [MAID-1085](https://maidsafe.atlassian.net/browse/MAID-1085) Unit test cases for Directory and File Helpers
    - [X] Implement REST DataTypes
        - [X] [MAID-1086](https://maidsafe.atlassian.net/browse/MAID-1086) Container & Blob types
            - [X] Implement Blob and Container types
            - [X] Implement FileWrapper trait for Blob
            - [X] Implement DirectoryListingWrapper trait for Container
        - [X] REST API methods in Container
            - [X] [MAID-1087](https://maidsafe.atlassian.net/browse/MAID-1087) Create Container & Get Container
            - [X] [MAID-1088](https://maidsafe.atlassian.net/browse/MAID-1088) List Containers, Update / Get Container Metadata
            - [X] [MAID-1089](https://maidsafe.atlassian.net/browse/MAID-1089) Delete Container
            - [X] [MAID-1090](https://maidsafe.atlassian.net/browse/MAID-1090) Create Blob
            - [X] [MAID-1091](https://maidsafe.atlassian.net/browse/MAID-1091) List Blobs
            - [X] [MAID-1092](https://maidsafe.atlassian.net/browse/MAID-1092) Get Blob
            - [X] [MAID-1098](https://maidsafe.atlassian.net/browse/MAID-1098) Update Blob Content
            - [X] [MAID-1093](https://maidsafe.atlassian.net/browse/MAID-1093) Get Blob Content
            - [X] [MAID-1094](https://maidsafe.atlassian.net/browse/MAID-1094) List Blob Version
            - [X] [MAID-1095](https://maidsafe.atlassian.net/browse/MAID-1095) Delete Blob
            - [X] [MAID-1096](https://maidsafe.atlassian.net/browse/MAID-1096) Copy Blob
            - [X] [MAID-1097](https://maidsafe.atlassian.net/browse/MAID-1097) Update / Get Blob Metadata
        - [X] [MAID-1099](https://maidsafe.atlassian.net/browse/MAID-1099) Unit test cases for API
    - [X] [MAID-1101](https://maidsafe.atlassian.net/browse/MAID-1101) Implement Version Cache (cache key,(blob/container) info to reduce network traffic)
    - [X] [MAID-1133](https://maidsafe.atlassian.net/browse/MAID-1133) Root Directory handling
- [X] Create Example:
    - [X] [MAID-1102](https://maidsafe.atlassian.net/browse/MAID-1102) Self authentication Example
    - [X] [MAID-1103](https://maidsafe.atlassian.net/browse/MAID-1103) Example to demonstrate Storage API

    ## [0.1] Finish sprint
    - [ ] [MAID-1104](https://maidsafe.atlassian.net/browse/MAID-1104) Validate above example against Local network / droplet
