// Find user based on text from Search text field 
function userLookup(usersLookupResults, error) {
    var userDisplayNameEncoded = encodeURIComponent(usersLookupResults);

    // Show loading icon
    toggle_visibility('userSearchResultsTable');

    var userSearchURI = 'https://graph.microsoft.com/v1.0/users?$filter=(startswith(displayName,\u0027' +
        userDisplayNameEncoded +
        '\u0027))\u0026$select=displayName,userPrincipalName,jobTitle,officeLocation,mail,department,OnPremisesSecurityIdentifier';

    var postBodyLookupData = {
        uri: userSearchURI,
        method: 'GET'
    };

    // Page Load Info via Azure Function
    var findUsers = document.querySelector('.usersLookupResults');
    zlFetch(
            funcUserSearch, {
                method: 'POST',
                body: postBodyLookupData,
                headers: {
                    "Content-Type": "application/json",
                },
            })
        .then(data => $('.usersLookupResults').html(data.body))
        .catch(error => {
            writeError(findUsers, error);
        });
}

// Get the selected user (row) UPN to use in query
// Risk Events Users 
function getUserDetails(tableName) {
    var table = document.getElementById(tableName);
    if (tableName === "riskEventsTable") {
        for (var i = 1; i < table.rows.length; i++) {
            table.rows[i].onclick = function () {
                var userUPN = this.cells[5].innerHTML;
                getDetailsviaBatch(userUPN, null);
            };
        }
    }
    // User Search Results Table Users
    if (tableName === "userSearchTable") {
        for (var i = 1; i < table.rows.length; i++) {
            table.rows[i].onclick = function () {
                var userUPN = this.cells[2].innerHTML;
                var userType = this.cells[5].innerHTML;
                getDetailsviaBatch(userUPN, userType);
            };
        }
    }
}

// Call Azure Function MSUser-Batch to retrieve users security datapoints
function getDetailsviaBatch(userprincipalname, userObjectType) {
    // Date Time Now
    var datetime = new Date();
    var datetimenow = datetime.toISOString();
    var datetimenowquery = datetimenow.substr(0, datetimenow.length - 5) + "z";

    // Date Time 30 Days ago
    var minusdays = new Date();
    minusdays.setDate(minusdays.getDate() - 30);
    var minusdaysago = minusdays.toISOString();
    var minusdaysagoquery = minusdaysago.substr(0, minusdaysago.length - 5) + "z";

    // After many attempts using different JSON generation modules this was the realiable way it always worked
    // for each request and the perculirarity of each backend MS Graph API
    // It's a bodge but it works consistently

    // SSPR Resets                
    var BatchID1 = '{"id": 1,' + '"method": "GET",' + '"url": "/auditLogs/directoryAudits?$filter=category eq ' +
        "'" + 'UserManagement' + "'" + ' and activityDateTime ge ' + minusdaysagoquery +
        ' and activityDateTime le ' + datetimenowquery + ' and startswith(activityDisplayName, ' + "'" +
        "Reset password" + "'" + ')"}';

    // User Sign-In
    var BatchID2 = '{"id": 2,' + '"method": "GET",' +
        '"url": "/auditLogs/signIns?$filter=createdDateTime%20ge%20' + minusdaysagoquery +
        '%20and%20createdDateTime%20le%20' + datetimenowquery + '%20and%20(userPrincipalName%20eq%20' + "'" +
        userprincipalname + "'" + ')&$top=10"}';

    // Identity Risks
    var BatchID3 = '{"id": 3,' + '"method": "GET",' +
        '"url": "/identityRiskEvents?$filter=userPrincipalName eq ' + "'" + userprincipalname + "'" + '"}';

    // User Details 
    var BatchID4 = '{"id": 4,' + '"method": "GET",' +
        '"url": "/users/' + userprincipalname +
        '?$select=displayName,givenName,surname,jobTitle,mail,mobilePhone,officeLocation,UserType,department,manager,city,OnPremisesSecurityIdentifier,userPrincipalName,accountEnabled,onPremisesDistinguishedName,onPremisesSamAccountName"}';

    // Registered Devices (Results consolidated with BatchID4 for display in the same DIV)
    var BatchID5 = '{"id": 5,' + '"method": "GET",' +
        '"url": "/users/' + userprincipalname +
        '/registeredDevices"}';

    // Add in POST and UserUPN
    var batchbody = '{"method":"POST","userUPN":"' + userprincipalname + '","bodyRequests":{"requests":[' +
        BatchID1 + "," + BatchID2 + "," + BatchID3 + "," + BatchID4 + "," + BatchID5 + ']}}';

    // Show Getting User animation
    toggle_visibility('gettingUserProfile');

    // Call MSUser-Batch Function to get data
    var fetchFullUsers = document.querySelector('.returnedSSPREvents');
    zlFetch(
            funcBatch, {
                method: 'POST',
                body: batchbody,
                headers: {
                    "Content-Type": "application/json",
                },
            })
        .then(data => processResponse(".returnedSSPREvents", data.body))
        .catch(error => {
            writeError(fetchFullUsers, error);
        });

    // ******************** REMOVE FOR LIVE TESTING *****************************
    // Call MSUser-PwnedPassword DEMO Function to get users AD Password Status               
    var demoPwnedUser = Math.floor(Math.random() * 2) + 1;
    //var pwnedBody = '{"user":' + demoPwnedUser + '}'                

    var pwnedBody = {
        user: demoPwnedUser
    };

    if ((userObjectType == "Hybrid") || (userObjectType == null)) {
        var fetchPwnedPWD = document.querySelector('.returnedPwnedPwdStatus');
        zlFetch(
                funcPwnedDemo, {
                    method: 'POST',
                    body: pwnedBody,
                    headers: {
                        "Content-Type": "application/json",
                    },
                })
            .then(data => $('.returnedPwnedPwdStatus').html(data.body))
            .catch(error => {
                writeError(fetchFullUsers, error);
            });
    }

    if (userObjectType == "B2B") {
        $('.returnedPwnedPwdStatus').html('<div class="progress"><div class="progress-bar progress-bar-success" role="progressbar" aria-valuenow="100"aria-valuemin="0" aria-valuemax="100" style="width:100%">B2B User. No password in AzureAD</div></div>');
    }
    if (userObjectType == "Cloud") {
        $('.returnedPwnedPwdStatus').html('<div class="progress"><div class="progress-bar progress-bar-info" role="progressbar" aria-valuenow="100"aria-valuemin="0" aria-valuemax="100" style="width:100%">Azure AD Only Account. Unable to verify</div></div>');
    }

    // ******************** REMOVE FOR LIVE TESTING *****************************

    // ******************** REMARK IN FOR LIVE TESTING *********************
    // Call MSUser-PwnedPassword Function to get users AD Password Status

    //  var pwnedBody = '{"user:"' + userprincipalname + '}"'
    //if (userObjectType == "Hybrid") {
    //  let fetchPwnedPWD = document.querySelector('.returnedPwnedPwdStatus')
    //  zlFetch(
    //    funcPwned, {
    //         method: 'POST',
    //         body: pwnedBody,
    //         headers: {
    //             "Content-Type": "application/json",
    //         },
    //     })
    // //.then(data => processResponse(".returnedPwnedPwdStatus", data.body))
    //   .then(data => $('.returnedPwnedPwdStatus').html(data.body))
    // .catch(error => {
    //     writeError(fetchFullUsers, error)
    // })
    //  }
    // ******************** REMARK IN FOR LIVE TESTING *********************

    // ******************** MFA Methods *****************************
    // var mfaBody = '{"query":"UPN%20eq%20' + userprincipalname + '"}'

    var mfaBody = {
        query: "UPN%20eq%20'" + userprincipalname + "'"
    };

    if ((userObjectType == "Hybrid") || (userObjectType == "Cloud") || (userObjectType == null)) {
        var fetchMFADetails = document.querySelector('.calcUserMFAProgress');
        zlFetch(
                funcMFA, {
                    method: 'POST',
                    body: mfaBody,
                    headers: {
                        "Content-Type": "application/json",
                    },
                })
            .then(data => processMFAResponse(".calcUserMFAProgress", data.body))
            .catch(error => {
                writeError(fetchMFA, error);
            });
    }

    if (userObjectType == "B2B") {
        $('.calcUserMFAProgress').html('<div class="progress"><div class="progress-bar progress-bar-info" role="progressbar" aria-valuenow="100"aria-valuemin="0" aria-valuemax="100" style="width:100%">B2B User. No MFA</div></div>');

    }

    // Parse MFA Response via Azure Funtion Responses
    function processMFAResponse(mfaDetailsDiv, mfaBatchResponseData) {

        Object.keys(mfaBatchResponseData).forEach(function (key) {
            console.log(key, mfaBatchResponseData[key]);
            // MFA Config
            if (key === "id1") {
                $('.calcUserMFAProgress').html(mfaBatchResponseData[key]);
            }
            if (key === "id2") {
                $('.returnedUserMFAMethods').html(mfaBatchResponseData[key]);
            }
        });        
    }

    // Parse Batched Queries via Azure Funtion Responses
    function processResponse(ssprEventsDiv, BatchResponseData) {

        Object.keys(BatchResponseData).forEach(function (key) {
            console.log(key, BatchResponseData[key]);
            // SSPR Reset Events
            if (key === "id1") {
                $('.returnedSSPREvents').html(BatchResponseData[key]);
            }

            if (key === "id1Count") {
                $('.calcSSPRSummary').html(
                    '<center><span class="fa-stack fa-2x"><i class="fa fa-square fa-stack-2x"></i><strong class="fa-stack-1x text-primary">' +
                    BatchResponseData[key] + '</strong></i></span><br/>events found</center>'
                );
            }

            // SignIn Events
            if (key === "id2") {
                var id2 = 1;
                $('.returnedSignInEvents').html(BatchResponseData[key]);
            }

            if (key === "id2Count") {
                $('.calcSignInSummary').html(
                    '<center><span class="fa-stack fa-2x"><i class="fa fa-square fa-stack-2x"></i><strong class="fa-stack-1x text-primary">' +
                    BatchResponseData[key] + '</strong></i></span><br/>events found</center>'
                );
            }

            // User Risk Events
            if (key === "id3") {
                var id3 = 1;
                $('.returnedUserRiskEvents').html(BatchResponseData[key]);
                // Display Risks Section                        
                toggle_visibility('userRiskandDetails');
            }

            if (key === "id3Count") {
                $('.calcUserRiskSummary').html(
                    '<center><span class="fa-stack fa-2x"><i class="fa fa-square fa-stack-2x"></i><strong class="fa-stack-1x text-primary">' +
                    BatchResponseData[key] + '</strong></i></span><br/>events found</center>'
                );
                // User Risk Progress Bar
                if (BatchResponseData[key] == 0) {
                    var userRiskProgressBar =
                        '<div class="progress"><div class="progress-bar progress-bar-success" role="progressbar" aria-valuenow="100" aria-valuemin="0" aria-valuemax="100" style="width:100%">No Risk Events Found</div></div>';
                }

                if (BatchResponseData[key] > 0 && BatchResponseData[key] <= 3) {
                    var userRiskProgressBar =
                        '<div class="progress"><div class="progress-bar progress-bar-warning" role="progressbar" aria-valuenow="66" aria-valuemin="0" aria-valuemax="100" style="width:66%">User Risk Events to review</div></div>';
                }

                if (BatchResponseData[key] > 3) {
                    var userRiskProgressBar =
                        '<div class="progress"><div class="progress-bar progress-bar-danger" role="progressbar" aria-valuenow="100" aria-valuemin="0" aria-valuemax="100" style="width:100%">User Risk Events to review</div></div>';
                }

                $('.calcUserRiskProgress').html(userRiskProgressBar);
            }

            // User Details
            if (key === "id4") {
                var id4 = 1;
                $('.returnedAADUserDetails').html(BatchResponseData[key]);

                // Display User Profile Section
                toggle_visibility('userScoreandProfile');
                toggle_visibility('userRecomendations');
            }

            // User Devices
            if (key === "id5Count") {
                $('.calcDevicesSummary').html(
                    '<center><span class="fa-stack fa-2x"><i class="fa fa-square fa-stack-2x"></i><strong class="fa-stack-1x text-primary">' +
                    BatchResponseData[key] + '</strong></i></span><br/>device(s) found</center>'
                );
            }
        });

        // display User Secure Score Summary
        userSScoreStarSummary();

        // Hide Getting User animation
        toggle_visibility('gettingUserProfile');
    }
}

function userSScoreStarSummary() {
    var mfaProfile = document.getElementsByClassName('calcUserMFAProgress')[0].innerHTML;
    var riskProfile = document.getElementsByClassName('calcUserRiskProgress')[0].innerHTML;
    var pwdProfile = document.getElementsByClassName('returnedPwnedPwdStatus')[0].innerHTML;
    var mfaScore = 0;
    var riskScore = 0;
    var pwdScore = 0;

    if (mfaProfile.indexOf('progress-bar-success') > -1) {
        mfaScore = 0;
    }
    if (mfaProfile.indexOf('progress-bar-warning') > -1) {
        mfaScore = 1;
    }
    if (mfaProfile.indexOf('progress-bar-danger') > -1) {
        mfaScore = 3;
    }
    if (riskProfile.indexOf('progress-bar-success') > -1) {
        riskScore = 0;
    }
    if (riskProfile.indexOf('progress-bar-warning') > -1) {
        riskScore = 1;
    }
    if (riskProfile.indexOf('progress-bar-danger') > -1) {
        riskScore = 3;
    }
    if (pwdProfile.indexOf('progress-bar-success') > -1) {
        pwdScore = 0;
    }
    if (pwdProfile.indexOf('progress-bar-danger') > -1) {
        pwdScore = 2.5;
    }
    if (mfaScore + riskScore + pwdScore > 0 && mfaScore + riskScore + pwdScore <= 2.5) {
        $('.userSScoreSummary').html(
            '<div class="card text-muted"><p class="card-text"><div><i class="fas fa-user-edit fa-5x"></i><b>Ok, but could be improved</b></br></div></p></div>'
        );
    }
    if (mfaScore + riskScore + pwdScore == 0) {
        $('.userSScoreSummary').html(
            '<div class="card text-muted"><p class="card-text"><div><i class="fas fa-user-check fa-5x"></i><b>Awesome. Great Profile</b></br></p></div>'
        );
    }
    if (mfaScore + riskScore + pwdScore >= 3) {
        $('.userSScoreSummary').html(
            '<div class="card text-muted"><p class="card-text"><div><i class="fas fa-user-times fa-5x"></i><b>Immediate Attention Required</b></br></p></div>'
        );
    }

    // Hide User Search
    document.getElementById('panelUsers').style.display = 'none';

    // Show New Search buton
    toggle_visibility('refresh');
}

function toggle_visibility(id) {
    var e = document.getElementById(id);
    if (e.style.display == 'block')
        e.style.display = 'none';
    else
        e.style.display = 'block';
}

// Page zoom to 75% for better layout. Seems to work on Chrome and Edge. 
function zoom() {
    document.body.style.zoom = "75%"; 
}

$(document).ready(function () {
    zoom();

    // Last 5 Active Risk Events
    var postBodydata = {
        uri: "https://graph.microsoft.com/beta/identityRiskEvents?$filter=riskEventStatus eq 'active'&$top=5",
        method: 'GET'
    };

    // Page Load Info via Azure Function
    var fetchUsers = document.querySelector('.returnedRiskEvents');
    zlFetch(
            funcUserRisk, {
                method: 'POST',
                body: postBodydata,
                headers: {
                    "Content-Type": "application/json",
                },
            })
        .then(data => $('.returnedRiskEvents').html(data.body))
        .catch(error => {
            writeError(fetchUsers, error);
        });

    // Secure Score
    var postSSBodydata = {
        uri: "https://graph.microsoft.com/beta/security/secureScores?$top=1",
        method: 'GET'
    };

    // Page Load Secure Score via Azure Function
    var fetchSecureScore = document.querySelector('.secureScoreResult');
    zlFetch(
            funcSecureScore, {
                method: 'POST',
                body: postSSBodydata,
                headers: {
                    "Content-Type": "application/json",
                },
            })
        .then(data => $('.secureScoreResult').html(data.body))
        .catch(error => {
            writeError(fetchSecureScore, error);
        });

    // Write Errors
    function writeError(errorDiv, error) {
        var errorMessage = document.createElement('div');
        errorMessage.classList.add('is-error');
        errorMessage.innerHTML = `<div> status: ${error.status}</div>
                <div> statusText: ${error.statusText} </div>
                <div> message: ${error.message} </div>
                <div> Azure Functions are still warming up. Try again </div>`;
        errorDiv.append(errorMessage);
    }
});