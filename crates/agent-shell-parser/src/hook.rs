use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct WorktreeCreateInput {
    pub name: String,
    pub cwd: String,
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct WorktreeRemoveInput {
    pub worktree_path: String,
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PreToolUseInput {
    pub tool_name: String,
    #[serde(default)]
    pub tool_input: serde_json::Value,
    #[serde(default)]
    pub cwd: Option<String>,
}

pub fn parse_input<T: serde::de::DeserializeOwned>() -> Result<T, crate::Error> {
    let input = std::io::read_to_string(std::io::stdin())?;
    Ok(serde_json::from_str(&input)?)
}
