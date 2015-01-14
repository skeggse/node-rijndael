{
  'variables': {
    'target_arch%': 'x64'
  },

  'target_defaults': {
    'default_configuration': 'Debug',
    'configurations': {
      'Debug': {
        'defines': ['DEBUG'],
        'msvs_settings': {
          'VCCLCompilerTool': {
            'RuntimeLibrary': 1 # static debug
          }
        }
      },
      'Release': {
        'defines': ['NODEBUG'],
        'msvs_settings': {
          'VCCLCompilerTool': {
            'RuntimeLibrary': 0 # static release
          }
        }
      }
    },
    'msvs_settings': {
      'VCLinkerTool': {
        'GenerateDebugInformation': 'true'
      }
    },
    'include_dirs': [
      '.',
      'include',
      'modules/algorithms',
      'modules/modes',
      'modules',
      'lib',
      'config/<(OS)/<(target_arch)'
    ],
    'defines': [
      'PIC',
      'HAVE_CONFIG_H'
    ]
  },

  'targets': [
    # libmcrypt
    {
      'target_name': 'mcrypt',
      'product_prefix': 'lib',
      'type': 'static_library',
      'sources': [
        'modules/algorithms/3-way.c',
        'modules/algorithms/cast-128.c',
        'modules/algorithms/gost.c',
        'modules/algorithms/rijndael-128.c',
        'modules/algorithms/safer64.c',
        'modules/algorithms/twofish.c',
        'modules/algorithms/arcfour.c',
        'modules/algorithms/cast-256.c',
        'modules/algorithms/loki97.c',
        'modules/algorithms/rijndael-192.c',
        'modules/algorithms/saferplus.c',
        'modules/algorithms/wake.c',
        'modules/algorithms/blowfish-compat.c',
        'modules/algorithms/des.c',
        'modules/algorithms/rijndael-256.c',
        'modules/algorithms/serpent.c',
        'modules/algorithms/xtea.c',
        'modules/algorithms/blowfish.c',
        'modules/algorithms/enigma.c',
        'modules/algorithms/rc2.c',
        'modules/algorithms/safer128.c',
        'modules/algorithms/tripledes.c',
        'modules/modes/cbc.c',
        'modules/modes/cfb.c',
        'modules/modes/ctr.c',
        'modules/modes/ecb.c',
        'modules/modes/ncfb.c',
        'modules/modes/nofb.c',
        'modules/modes/ofb.c',
        'modules/modes/stream.c',
        'lib/mcrypt_extra.c',
        'lib/mcrypt.c',
        'lib/bzero.c',
        'lib/xmemory.c',
        'lib/mcrypt_modules.c',
        'lib/win32_comp.c',
        'lib/mcrypt_threads.c',
        'lib/mcrypt_symb.c'
      ],
      'conditions': [
        ['OS=="linux"', {
          'cflags': [
            '-Wall', '-std=c99', '-g'
          ]
        }]
      ]
    },

    {
      'target_name': 'aes_test',
      'type': 'executable',
      'dependencies': ['mcrypt'],
      'sources': [
        'src/aes_test.c'
      ],
      'conditions': [
        ['OS=="linux"', {
          'cflags': [
            '-Wall', '-std=c99', '-g'
          ]
        }]
      ]
    },

    {
      'target_name': 'cipher_test',
      'type': 'executable',
      'dependencies': ['mcrypt'],
      'sources': [
        'src/cipher_test.c'
      ],
      'conditions': [
        ['OS=="linux"', {
          'cflags': [
            '-Wall', '-std=c99', '-g'
          ]
        }]
      ]
    }
  ]
}
