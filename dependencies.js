const fs = require('fs');
//const { constants } = require('http2');

const scaInputFileName = 'scaResults.json'; // 'results.json'
const GitlabOutputFileName = 'output-sca-vulnerabilites.json'; // 'veracode-results.json'
var vulns=[];
var vulnerabilities=[];
var remeds=[];
var remediations=[];
var mapSeverity = "";


const convertSCAResultFileToJSONReport = (inputFileName,outputFileName) => {
    var results = {};
    var vulnResults={};

    var rawdata = fs.readFileSync(inputFileName);
    results = JSON.parse(rawdata);
    console.log('SCA Scan results file found and parsed - validated JSON file');


        var issues = results.records[0].vulnerabilities;
        numberOfVulns = issues.length
        console.log('Vulnerabilities count: '+issues.length);

        var i = 0;
        while (i < numberOfVulns) {
            var  refLink = results.records[0].vulnerabilities[i].libraries[0]._links.ref;
            var libRef = refLink.split("/");

            var oldSeverity = parseInt(results.records[0].vulnerabilities[i].cvssScore);

            //severity mapping
            if (oldSeverity == '0.0')
              mapSeverity = 'Unknown'
            else if (oldSeverity >= '0.1' && oldSeverity < '3.9')
              mapSeverity = 'Low'
            else if (oldSeverity >= '4.0' && oldSeverity < '6.9')
              mapSeverity = 'Medium'
            else if (oldSeverity >= '7.0' && oldSeverity < '8.9')
              mapSeverity = 'High'
            else if (oldSeverity >= '9.0')
              mapSeverity = 'Critical'

            console.log('Full String: '+results.records[0].vulnerabilities[i].libraries[0]._links.ref)
            console.log('RefLink: '+refLink)
            console.log('LibRef: '+libRef[4])
            console.log('ID: '+results.records[0].libraries[libRef[4]].versions[0].sha1)

            // construct Vulnerabilities for reports file
            vulns = {
                id: results.records[0].libraries[libRef[4]].versions[0].sha1,
                category: "dependency_scanning",
                name: results.records[0].vulnerabilities[i].title+' at '+results.records[0].libraries[libRef[4]].name,
                message: '',
                description: results.records[0].libraries[libRef[4]].description+' - '+results.records[0].vulnerabilities[i].overview,
                severity: mapSeverity,
                solution: results.records[0].vulnerabilities[i].libraries[0].details[0].fixText,
                scanner: {
                    id: "Veracode Agent Based SCA",
                    name: "Veracode Agent Based SCA"
                  },
                  location: {
                    file: "",
                    dependency: {
                      package: {
                        name: results.records[0].libraries[libRef[4]].coordinateType+':'+results.records[0].libraries[libRef[4]].coordinate1+':'+results.records[0].libraries[libRef[4]].coordinate2,
                      },
                      version: results.records[0].libraries[libRef[4]].versions[0].version
                    }
                  },
                  identifiers: [
                    {
                      type: "Veracode Agent Based SCA",
                      name: "Veracode-"+results.metadata.requestDate,
                      value: results.metadata.requestDate,
                      url: results.records[0].libraries[libRef[4]].bugTrackerUrl
                    }
                  ],
                  links: [
                    {
                      url: results.records[0].libraries[libRef[4]].versions[0]._links.html
                    },
                    {
                      url: results.records[0].vulnerabilities[i]._links.html
                    },
                    {
                      url: results.records[0].vulnerabilities[i].libraries[0].details[0].patch
                    }
                  ]
            };

            remeds = {
                              fixes: 
                              [
                                {
                                  id: results.records[0].libraries[libRef[4]].versions[0].sha1
                                }
                              ],
                              summary: results.records[0].vulnerabilities[i].libraries[0].details[0].fixText,
                              diff: ""
                            };
            
            i++;
            console.log(vulns);
            console.log(remeds);
            vulnerabilities.push(JSON.stringify(vulns));
            remediations.push(JSON.stringify(remeds));
        }
        //vulns & remediations start
        var vulnsStart = '{"version": "2.0","vulnerabilities":[';
        var remediationsStart = '"remediations": [';
        // vulns & remediations finish
        var vulnsEnd = ']';
        var remediationsEnd = ']}';
        //create full report
        var fullReportString = vulnsStart+vulnerabilities+vulnsEnd+','+remediationsStart+remediations+remediationsEnd
        var vulnerabilitiesReport = JSON.parse(fullReportString);
        console.log('Vulnerabilities:'+fullReportString);


        // save to file
        fs.writeFileSync(outputFileName,fullReportString);
        console.log('Report file created: '+outputFileName);
}

//try {
    convertSCAResultFileToJSONReport(scaInputFileName,GitlabOutputFileName);
//} 
//catch (error) {
//    core.setFailed(error.message);
//}

module.exports = {
    converSCAResulst: convertSCAResultFileToJSONReport,
}