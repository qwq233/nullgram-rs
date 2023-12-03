use std::fs::File;
use std::os::raw::c_uchar;

use integrity::{zip_util, signature_block, v2signature};
use android_logger_lite as log;
use jni::signature::ReturnType;
use jni::{sys, JavaVM, JNIEnv};
use jni::objects::{JString, JValue, JObject};


pub mod integrity;

#[no_mangle]
pub unsafe extern "C" fn verify_signature<'local>(ptr: *mut sys::JavaVM) -> c_uchar {
    let env = JavaVM::from_raw(ptr);
    let env = match env {
        Ok(env) => env,
        Err(e) => {
            log::e("librs".to_string(), format!("env: {}", e));
            return 0;
        }
    };
    let env = env.get_env();
    let mut env = match env {
        Ok(env) => env,
        Err(e) => {
            log::e("librs".to_string(), format!("env: {}", e));
            return 0;
        }
    };

    let path = match get_apk_path(&mut env) {
        Some(path) => path,
        None => {
            return 0;
        }
    };
    let mut file = File::open(path).unwrap();

    let eocd = zip_util::parse_eocd(&mut file).unwrap();
    let signature_block = signature_block::parse_signature_block(&mut file, eocd.cd_offset as u64).unwrap();
    for id_pair in &signature_block.id_pairs {
        if id_pair.id == 0x7109871a {
            if let Some(v2_signature) = v2signature::get_v2signature(&id_pair.value) {
                let md5 = format!("{:X}", md5::compute(v2_signature)).to_ascii_uppercase();
                let md5 = md5.as_str();
                match md5 {
                    "79F5947F1AC75D23F509DDC97A749DC7" => {
                        return 1;
                    },
                    "999014B8010E81DC52825616228ECEB9" => {
                        return 2;
                    }
                    _ => {
                        return 0;
                    }
                }
            } else {
                return 0;
            }
        }
    };
    return 0;
}

#[allow(non_snake_case)]
pub unsafe fn get_apk_path(env: &mut JNIEnv) -> Option<String> {
    let cMainClass = env.find_class("org/telegram/messenger/ApplicationLoader").unwrap();

    let cMainClass = env.new_global_ref(cMainClass).unwrap();

    let cClass = env.find_class("java/lang/Class").unwrap();

    let mClassLoader = env.get_method_id(cClass, "getClassLoader", "()Ljava/lang/ClassLoader;").unwrap();
    let classLoader = env.call_method_unchecked(cMainClass, mClassLoader, ReturnType::Object, &[]).unwrap();
    let classLoader = classLoader.l().expect("classLoader");

    let classLoader = env.new_global_ref(classLoader).unwrap();

    let manifestPath = env.new_string("AndroidManifest.xml").unwrap();
    let url = env.call_method(classLoader, "findResource", "(Ljava/lang/String;)Ljava/net/URL;", &[JValue::Object(&manifestPath.into())]).expect("findResource");
    let url = JObject::try_from(url).unwrap();

    let filePath = env.call_method(url, "getPath", "()Ljava/lang/String;", &[]).expect("getPath");
    let filePath = JString::from(JObject::try_from(filePath).unwrap());
    let filePath = env.get_string(&filePath).unwrap();
    let filePath = filePath.to_str().unwrap();
    let filePath = filePath[5..filePath.len() - 21].to_string();

    return Some(filePath);
}
