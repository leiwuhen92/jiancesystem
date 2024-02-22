import pymongo
# from werkzeug.routing import ValidationError
from config import mongo_ip, mongo_port
import logging
import json
import gridfs
import bson


mongo_client = pymongo.MongoClient(host=mongo_ip, port=mongo_port, connect=False, username="podding", password="Podding_123", authSource="admin")
logging.basicConfig(level=logging.INFO, format="[%(asctime)s][%(levelname)s][%(filename)s:%(lineno)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")


def field_length_limit(min_length, max_length):
    def validate(s):
        if type(s) != str:
            raise ValueError("The field must be String.")
        if min_length < len(s) <= max_length:
            return s
        raise ValueError("The field's lentgh must %d-%d characters." % (min_length, max_length))

    return validate


class DbGidFS(object):
    def __init__(self, mongo_client, db, table):
        self.db = mongo_client[db]
        self.collection = self.db[table]

        # 建索引
        self.db.fs.files.create_index([('filename', 1)], unique=True)
        self.db.fs.chunks.create_index([('files_id', 1), ('n', 1)], unique=True)
        self.gfs = gridfs.GridFS(self.db)

    def insert_or_update_table(self, uploadId, collection_data=None, gfs_Data=None):
        if self.collection.find_one({"uploadId": uploadId}):
            # 更新table中
            if gfs_Data:
                self.insert_or_read(uploadId, gfs_Data)
        else:
            logging.info("insert table")
            if collection_data:
                self.collection.insert_one(collection_data)

    def insert_or_read(self, uploadId, content_dict):
        file_content_bytes = bytes(json.dumps(content_dict), encoding='utf-8')
        # 转换为mongodb的二进制数据存储形式
        content = bson.binary.Binary(file_content_bytes)

        try:
            result = self.db.fs.files.find_one({'filename': uploadId})  # dict
            if result:
                logging.info('已经存在该文件')
                file_id = result['_id']
                output= self.gfs.get(file_id).read()
                logging.debug(output)
            else:
                self.gfs.put(content, filename=uploadId)
                logging.info("upload ok")
        except Exception as e:
            logging.error(e)


if __name__ == '__main__':
    init_data = {
        "md5": "5350aedba1c235c5a4c24ff60c3298a2",
        "sha256": "d1c925edf5352cf108c19428a265d6e230445f90828729b85ffef799031d66b5",
        "file_name": "geektime-rust-master.zip",
        "file_path": "C:/Users/zhangqiang/Desktop/restfulapi/firmwares/geektime-rust-master.zip",
        "name": "geektime-rust-master分析",
        "version": "1.99.0",
        "detectypes": ["1", "2", "3", "4", "5", "6", "7"],
        "uploadId": 105551
    }
    update_data = {
        "detectStatus": "已完成",
        "detectErr": "",
        "detectList": [
            {
                "algorithmType": 3,
                "algorithmName": "基本分析",
                "algorithmStatus": 3,
                "algorithmErr": "",
                "algorithmResult": {
                    "details": [
                        {
                            "files": 2,
                            "language": "XML",
                            "lines": 118924,
                            "size": "32.03 MB",
                            "size_int": 33585546
                        },
                        {
                            "files": 359,
                            "language": "Rust",
                            "lines": 22860,
                            "size": "749.23 KB",
                            "size_int": 767208
                        }
                    ],
                    "error_count": 0,
                    "success_count": 383,
                    "total_count": 383,
                    "total_files": 383,
                    "total_lines": 142922,
                    "total_size": "32.80 MB",
                    "total_size_int": 34391783,
                    "name": "geektime-rust-master基本分析",
                    "file_name": "geektime-rust-master.zip"
                }
            },
            {
                "algorithmType": 4,
                "algorithmName": "代码规范分析",
                "algorithmStatus": 3,
                "algorithmErr": "",
                "algorithmResult": {
                    "C": "/data/storage/detect/b26fe44e-843e-4f66-ade8-9b7986de1703/code_lint_C_1.txt",
                    "Kotlin": "/data/storage/detect/b26fe44e-843e-4f66-ade8-9b7986de1703/code_lint_Kotlin_2.txt",
                    "Python": "/data/storage/detect/b26fe44e-843e-4f66-ade8-9b7986de1703/code_lint_Python_1.txt"
                }
            },
            {
                "algorithmType": 7,
                "algorithmName": "克隆代码分析",
                "algorithmStatus": 3,
                "algorithmErr": "",
                "algorithmResult": {
                    "detectResult": {
                        "geektime-rust-master/01_stack_heap/misc/varargs.c": [
                            {
                                "component": "geektime-rust",
                                "file": "01_stack_heap/misc/varargs.c",
                                "file_hash": "581b0cc9ffcee6c5b76d9ff2bd8fb2e0",
                                "file_url": "https://osskb.org/api/file_contents/581b0cc9ffcee6c5b76d9ff2bd8fb2e0",
                                "id": "file",
                                "latest": "ff5f037",
                                "licenses": [
                                    {
                                        "checklist_url": "https://www.osadl.org/fileadmin/checklists/unreflicenses/Apache-2.0.txt",
                                        "copyleft": "no",
                                        "name": "Apache-2.0",
                                        "osadl_updated": "2023-12-10T03:40:00+00:00",
                                        "patent_hints": "yes",
                                        "source": "license_file",
                                        "url": "https://spdx.org/licenses/Apache-2.0.html"
                                    }
                                ],
                                "lines": "all",
                                "matched": "100%",
                                "oss_lines": "all",
                                "purl": [
                                    "pkg:github/tyrchen/geektime-rust"
                                ],
                                "release_date": "2021-10-17",
                                "server": {
                                    "kb_version": {
                                        "daily": "23.12.14",
                                        "monthly": "23.11"
                                    },
                                    "version": "5.3.3"
                                },
                                "source_hash": "581b0cc9ffcee6c5b76d9ff2bd8fb2e0",
                                "status": "pending",
                                "url": "https://github.com/tyrchen/geektime-rust",
                                "url_hash": "1fe0b947a1eaabad86d47fe2acda1089",
                                "vendor": "tyrchen",
                                "version": "daf3a48"
                            }
                        ],
                        "geektime-rust-master/01_stack_heap/src/error.rs": [
                            {
                                "id": "none",
                                "server": {
                                    "kb_version": {
                                        "daily": "23.12.14",
                                        "monthly": "23.11"
                                    },
                                    "version": "5.3.3"
                                }
                            }
                        ]
                    },
                    "directory": [
                        {
                            "children": [
                                {
                                    "key": "geektime-rust-master/Cargo.toml",
                                    "label": "Cargo.toml"
                                },
                                {
                                    "key": "geektime-rust-master/LICENSE",
                                    "label": "LICENSE"
                                },
                                {
                                    "key": "geektime-rust-master/README.md",
                                    "label": "README.md"
                                },
                                {
                                    "key": "geektime-rust-master/deny.toml",
                                    "label": "deny.toml"
                                },
                                {
                                    "children": [
                                        {
                                            "children": [
                                                {
                                                    "key": "geektime-rust-master/.github/workflows/build.yml",
                                                    "label": "build.yml"
                                                }
                                            ],
                                            "key": "geektime-rust-master/.github/workflows",
                                            "label": "workflows"
                                        }
                                    ],
                                    "key": "geektime-rust-master/.github",
                                    "label": ".github"
                                },
                                {
                                    "children": [
                                        {
                                            "key": "geektime-rust-master/01_stack_heap/Cargo.toml",
                                            "label": "Cargo.toml"
                                        },
                                        {
                                            "children": [
                                                {
                                                    "key": "geektime-rust-master/01_stack_heap/misc/varargs.c",
                                                    "label": "varargs.c"
                                                }
                                            ],
                                            "key": "geektime-rust-master/01_stack_heap/misc",
                                            "label": "misc"
                                        },
                                        {
                                            "children": [
                                                {
                                                    "key": "geektime-rust-master/01_stack_heap/src/error.rs",
                                                    "label": "error.rs"
                                                },
                                                {
                                                    "key": "geektime-rust-master/01_stack_heap/src/pointer.rs",
                                                    "label": "pointer.rs"
                                                },
                                                {
                                                    "key": "geektime-rust-master/01_stack_heap/src/string.rs",
                                                    "label": "string.rs"
                                                }
                                            ],
                                            "key": "geektime-rust-master/01_stack_heap/src",
                                            "label": "src"
                                        }
                                    ],
                                    "key": "geektime-rust-master/01_stack_heap",
                                    "label": "01_stack_heap"
                                },
                                {
                                    "children": [
                                        {
                                            "key": "geektime-rust-master/02_concepts/Cargo.toml",
                                            "label": "Cargo.toml"
                                        },
                                        {
                                            "children": [
                                                {
                                                    "key": "geektime-rust-master/02_concepts/misc/crash.c",
                                                    "label": "crash.c"
                                                },
                                                {
                                                    "key": "geektime-rust-master/02_concepts/misc/type.c",
                                                    "label": "type.c"
                                                },
                                                {
                                                    "key": "geektime-rust-master/02_concepts/misc/type.py",
                                                    "label": "type.py"
                                                }
                                            ],
                                            "key": "geektime-rust-master/02_concepts/misc",
                                            "label": "misc"
                                        },
                                        {
                                            "children": [
                                                {
                                                    "key": "geektime-rust-master/02_concepts/src/shape.rs",
                                                    "label": "shape.rs"
                                                }
                                            ],
                                            "key": "geektime-rust-master/02_concepts/src",
                                            "label": "src"
                                        }
                                    ],
                                    "key": "geektime-rust-master/02_concepts",
                                    "label": "02_concepts"
                                }
                            ],
                            "key": "geektime-rust-master",
                            "label": "geektime-rust-master"
                        }
                    ]
                }
            },
            {
                "algorithmType": 1,
                "algorithmName": "成分分析",
                "algorithmStatus": 3,
                "algorithmErr": "",
                "algorithmResult": {
                    "dep_result": [
                        {
                            "language": "Rust",
                            "name": "reqwest",
                            "namespace": "",
                            "type": "cargo",
                            "version": "0.11"
                        },
                        {
                            "language": "Node JS",
                            "name": "zopflipng-bin",
                            "namespace": "",
                            "type": "npm",
                            "version": "6.0.1"
                        }
                    ]
                }
            },
            {
                "algorithmType": 2,
                "algorithmName": "许可证合规分析",
                "algorithmStatus": 3,
                "algorithmErr": "",
                "algorithmResult": {
                    "dual_license:": False,
                    "file_number": 528,
                    "has_license:": 6,
                    "license:": [
                        "apache-2.0"
                    ],
                    "license_conflict:": [
                        {
                            "cfile": "geektime-rust-master/32_xunmi_py/fixtures/wiki_00.xml",
                            "confict": [
                                {
                                    "clicense": "llgpl",
                                    "plicense": "apache-2.0",
                                    "term": [
                                        "代码开源",
                                        "相同许可证"
                                    ]
                                },
                                {
                                    "clicense": "gpl-2.0-plus",
                                    "plicense": "apache-2.0",
                                    "term": [
                                        "代码开源",
                                        "相同许可证",
                                        "专利使用"
                                    ]
                                }
                            ],
                            "pfile": "geektime-rust-master/LICENSE"
                        },
                        {
                            "cfile": "geektime-rust-master/32_xunmi_py/xunmi-py/fixtures/wiki_00.xml",
                            "confict": [
                                {
                                    "clicense": "llgpl",
                                    "plicense": "apache-2.0",
                                    "term": [
                                        "代码开源",
                                        "相同许可证"
                                    ]
                                },
                                {
                                    "clicense": "gpl-2.0-plus",
                                    "plicense": "apache-2.0",
                                    "term": [
                                        "代码开源",
                                        "相同许可证",
                                        "专利使用"
                                    ]
                                }
                            ],
                            "pfile": "geektime-rust-master/LICENSE"
                        }
                    ],
                    "license_count:": [
                        {
                            "category": "Copyleft",
                            "count": 3,
                            "name": "gpl-3.0"
                        },
                        {
                            "category": "Copyleft Limited",
                            "count": 2,
                            "name": "llgpl"
                        },
                        {
                            "category": "Copyleft",
                            "count": 2,
                            "name": "gpl-2.0-plus"
                        },
                        {
                            "category": "Copyleft",
                            "count": 2,
                            "name": "gpl-1.0"
                        },
                        {
                            "category": "Permissive",
                            "count": 2,
                            "name": "apache-2.0"
                        },
                        {
                            "category": "Copyleft",
                            "count": 2,
                            "name": "gpl-3.0-plus"
                        },
                        {
                            "category": "Copyleft",
                            "count": 2,
                            "name": "gpl-2.0"
                        },
                        {
                            "category": "Copyleft Limited",
                            "count": 2,
                            "name": "lgpl-2.1-plus"
                        },
                        {
                            "category": "Copyleft Limited",
                            "count": 2,
                            "name": "lgpl-2.0-plus"
                        },
                        {
                            "category": "Permissive",
                            "count": 1,
                            "name": "llvm-exception"
                        },
                        {
                            "category": "Permissive",
                            "count": 1,
                            "name": "mit"
                        },
                        {
                            "category": "Permissive",
                            "count": 1,
                            "name": "bsd-new"
                        },
                        {
                            "category": "Permissive",
                            "count": 1,
                            "name": "bsd-simplified"
                        },
                        {
                            "category": "Public Domain",
                            "count": 1,
                            "name": "cc0-1.0"
                        }
                    ],
                    "license_file:": "geektime-rust-master/LICENSE",
                    "license_kind:": 14,
                    "license_total:": 24,
                    "license_tree:": {
                        "children": [
                            {
                                "children": [],
                                "collapsed": False,
                                "has_conflict": False,
                                "is_guide": False,
                                "name": "deny.toml",
                                "value": [
                                    "llvm-exception",
                                    "mit",
                                    "apache-2.0",
                                    "bsd-new",
                                    "gpl-3.0",
                                    "bsd-simplified",
                                    "cc0-1.0"
                                ]
                            },
                            {
                                "children": [
                                    {
                                        "children": [
                                            {
                                                "children": [],
                                                "collapsed": False,
                                                "has_conflict": True,
                                                "is_guide": True,
                                                "name": "wiki_00.xml",
                                                "value": [
                                                    "llgpl",
                                                    "gpl-2.0-plus",
                                                    "gpl-1.0",
                                                    "gpl-3.0",
                                                    "gpl-3.0-plus",
                                                    "gpl-2.0",
                                                    "lgpl-2.1-plus",
                                                    "lgpl-2.0-plus"
                                                ]
                                            }
                                        ],
                                        "collapsed": False,
                                        "has_conflict": False,
                                        "is_guide": True,
                                        "name": "fixtures",
                                        "value": []
                                    },
                                    {
                                        "children": [
                                            {
                                                "children": [
                                                    {
                                                        "children": [],
                                                        "collapsed": False,
                                                        "has_conflict": True,
                                                        "is_guide": True,
                                                        "name": "wiki_00.xml",
                                                        "value": [
                                                            "llgpl",
                                                            "gpl-2.0-plus",
                                                            "gpl-1.0",
                                                            "gpl-3.0",
                                                            "gpl-3.0-plus",
                                                            "gpl-2.0",
                                                            "lgpl-2.1-plus",
                                                            "lgpl-2.0-plus"
                                                        ]
                                                    }
                                                ],
                                                "collapsed": False,
                                                "has_conflict": False,
                                                "is_guide": True,
                                                "name": "fixtures",
                                                "value": []
                                            }
                                        ],
                                        "collapsed": False,
                                        "has_conflict": False,
                                        "is_guide": True,
                                        "name": "xunmi-py",
                                        "value": []
                                    }
                                ],
                                "collapsed": False,
                                "has_conflict": False,
                                "is_guide": True,
                                "name": "32_xunmi_py",
                                "value": []
                            }
                        ],
                        "collapsed": True,
                        "has_conflict": True,
                        "is_guide": True,
                        "name": "geektime-rust-master",
                        "value": [
                            "apache-2.0"
                        ]
                    },
                    "no_license:": 522
                }
            },
            {
                "algorithmType": 5,
                "algorithmName": "C语言代码漏洞检测",
                "algorithmStatus": 3,
                "algorithmErr": "",
                "algorithmResult": {
                    "detail": {
                        "CWE119": {
                            "vulnerability": [
                                {
                                    "file_path": "net-tools-2.10/statistics.c",
                                    "function_line": "481",
                                    "function_name": "process6_fd"
                                },
                                {
                                    "file_path": "net-tools-2.10/lib/rose.c",
                                    "function_line": "80",
                                    "function_name": "ROSE_input"
                                }
                            ]
                        },
                        "CWE399": {
                            "vulnerability": []
                        }
                    },
                    "output_file": "/data/storage/detect/acb2dfef-595c-421a-9977-09715bc19e0b/multicodeCheck.txt"
                }
            },
            {
                "algorithmType": 6,
                "algorithmName": "标准合规检查",
                "algorithmStatus": 3,
                "algorithmErr": "",
                "algorithmResult": {
                    "errList": [
                        {
                            "file_path": "geektime-rust-master/01_stack_heap/misc/varargs.c",
                            "id": "misra-c2012-2.7",
                            "line": "18",
                            "message": "There should be no unused parameters in functions\n",
                            "severity": "style"
                        },
                        {
                            "file_path": "geektime-rust-master/11_memory/misc/test.c",
                            "id": "misra-c2012-21.6",
                            "line": "2",
                            "message": "The Standard Library input/output routines shall not be used\n",
                            "severity": "style"
                        }
                    ],
                    "output_file": "/data/storage/detect/94f62798-a789-452a-b8b7-05aad8fc23b3/checkCC++.txt"
                }
            }
        ]
    }
    id = 105551

    db_gridfs = DbGidFS(mongo_client, "gridfs_yuanxi", "yaunxi_collection")
    db_gridfs.insert_or_update_table(id, init_data, update_data)
