node{

    stage("Load Master Jenkins file"){
        checkout([$class: 'GitSCM', branches: [[name: "feature/OPS-367"]],
                                    doGenerateSubmoduleConfigurations: false,
                                    extensions: [[ $class: 'RelativeTargetDirectory',
                                                   relativeTargetDir: 'JenkinsFile']],
                                    submoduleCfg: [],
                                    userRemoteConfigs: [[ credentialsId: 'Jenkins_Gitlab',
                                                          url: 'git@gitlab.com:csw_beta_developers/devops/jenkins-pipeline.git']]
                 ])
            jenkinsfile= load 'JenkinsFile/csw-ci-cd.pipeline'
    }
}

