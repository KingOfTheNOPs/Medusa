function(task, responses){
    if(task.status.includes("error")) return {"plaintext": responses.join("")};
    if(responses.length === 0) return {"plaintext": "No response yet from agent..."};
    try {
        const data = JSON.parse(responses[0]);
        const rows = data.map(item => ({
            "remove": {"button": {"name": "Remove", "type": "task", "ui_feature": "medusa:unregister_coff",
                "parameters": {"coff_name": item.name}, "openDialog": false, "getConfirmation": true}},
            "name": {"plaintext": item.name}, "size": {"plaintext": String(item.size)}, "sha256": {"plaintext": item.sha256}
        }));
        return {"table": [{"headers": [
            {"plaintext": "remove", "type": "button", "width": 100, "disableSort": true},
            {"plaintext": "name", "type": "string", "fillWidth": true},
            {"plaintext": "size", "type": "number", "width": 100},
            {"plaintext": "sha256", "type": "string", "fillWidth": true}
        ], "rows": rows, "title": "COFF objects registered in memory"}]};
    } catch(error) { return {"plaintext": responses.join("")}; }
}
