node{

    stage("Load Master Jenkins file"){
        checkout([$class: 'GitSCM', branches: [[name: "feature/OPS-367"]],
                                    doGenerateSubmoduleConfigurations: false,
                                    extensions: [[ $class: 'RelativeTargetDirectory',
                                                   relativeTargetDir: 'JenkinsFile']],
                                    submoduleCfg: [],
                                    userRemoteConfigs: [[ credentialsId: 'securin-codecommit',
                                                          url: 'https://git-codecommit.us-west-2.amazonaws.com/v1/repos/jenkins-pipeline.git']]
                 ])
            jenkinsfile= load 'JenkinsFile/viq-ci-cd.pipeline'
    }
}

