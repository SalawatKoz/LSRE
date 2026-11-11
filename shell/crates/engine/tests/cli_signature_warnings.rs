use craft_anything_engine::{CallOptions, Caller, Engine, ToolOutput};
use craft_anything_testkit::managed as fx;
use serde_json::{Value, json};

fn call(engine: &Engine, tool: &str, params: Value) -> Value {
    let ToolOutput::Evidence(record) = engine.call(tool, params, CallOptions::new(Caller::Mcp)).unwrap() else {
        panic!("expected evidence from {tool}");
    };
    assert!(record.verify());
    serde_json::to_value(&*record).unwrap()
}

fn has_signature_note(result: &Value) -> bool {
    result["limitations"].as_array().unwrap().iter().any(|l| l["message"].as_str().is_some_and(|m| m.contains("trailing bytes")))
}

#[test]
fn padded_signatures_keep_types_and_surface_a_limitation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Sample.dll");
    for padded in [false, true] {
        let bytes = if padded { fx::managed_assembly_with_padded_signatures(1) } else { fx::managed_assembly(1) };
        std::fs::write(&path, &bytes).unwrap();
        let engine = Engine::new(craft_anything_engine::testing::session());
        for tool in ["managed_assembly_show", "managed_members_list", "managed_native_calls_list"] {
            let result = call(&engine, tool, json!({"path": path}));
            assert_eq!(has_signature_note(&result), padded, "{tool}: {result}");
        }
        let graph = call(&engine, "managed_app_graph_build", json!({"input": path}));
        assert_eq!(has_signature_note(&graph), padded);
        let members = call(&engine, "managed_members_list", json!({"path": path, "type_names": ["Sample.Calculator"], "include_il": true}));
        let calc = &members["result"]["types"][0];
        assert_eq!(calc["fields"][0]["type"], "int");
        assert_eq!(calc["methods"][0]["signature"], "public int Add(int a, int b)");
        assert_eq!(calc["methods"][1]["body"]["locals"][0], "int");
        assert_eq!(members["result"]["warnings"].as_array().unwrap().len(), usize::from(padded));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
}

#[test]
fn derived_managed_views_retain_the_signature_limitation() {
    let dir = tempfile::tempdir().unwrap();
    let padded = dir.path().join("Padded.dll");
    let clean = dir.path().join("Clean.dll");
    let native = dir.path().join("craft.dll");
    std::fs::write(&padded, fx::managed_assembly_with_padded_signatures(1)).unwrap();
    std::fs::write(&clean, fx::managed_assembly(1)).unwrap();
    std::fs::write(&native, craft_anything_testkit::pe64()).unwrap();
    let engine = Engine::new(craft_anything_engine::testing::session());
    let compare = call(&engine, "managed_assemblies_compare", json!({"left": padded, "right": clean}));
    assert!(has_signature_note(&compare));
    for change in ["changed", "renamed_or_moved", "added", "removed", "field_changes"] {
        assert_eq!(compare["result"]["counts"][change], 0, "{change}: {compare}");
    }
    let verify = call(&engine, "managed_native_calls_verify", json!({"managed": padded, "native": [native]}));
    assert!(has_signature_note(&verify));
    assert_eq!(verify["result"]["pinvokes"][0]["status"], "found");
    let reconstruction = call(&engine, "managed_reconstruction_check", json!({"members": padded, "source_text": fx::RECONSTRUCTION_CS}));
    assert!(has_signature_note(&reconstruction));
    assert_eq!(reconstruction["result"]["counts"]["missing"], 0);
}
