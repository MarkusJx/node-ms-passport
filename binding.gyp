{
    "targets": [{
        "conditions":[
            ["OS=='win'", {
                'libraries': [
                    '../NodeMsPassport/x64/Release/NodeMsPassport',
                ]
            }],
            ["OS=='mac'", {
                'xcode_settings': {
                    'GCC_ENABLE_CPP_EXCEPTIONS': 'YES',
                    'OTHER_CFLAGS': [
                        '-std=c++17',
                        '-stdlib=libc++'
                    ]
                }
            }]
        ],
        "target_name": "passport",
        "cflags!": [ "-fno-exceptions" ],
        "cflags_cc!": [ "-fno-exceptions", "/EHsc" ],
        "sources": [
            "src/msPassport.cpp",
        ],
        'include_dirs': [
            "<!@(node -p \"require('node-addon-api').include\")",
            "NodeMsPassport/NodeMsPassport"
        ],
        'dependencies': [
            "<!(node -p \"require('node-addon-api').gyp\")"
        ],
        'defines': [ 'NAPI_CPP_EXCEPTIONS' ],
        'msvs_settings': {
            'VCCLCompilerTool': {
                'ExceptionHandling': '1',
                'AdditionalOptions': ['/EHsc', '/std:c++17']
            }
        }
    }]
}