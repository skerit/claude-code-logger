#!/usr/bin/env node

/**
 * Claude API Logger - Captures Claude API requests and responses
 * Usage: claude-log [options] [claude options]
 * 
 * Options:
 *  --log_dir=DIR     Specify directory for logs (default: ./logs)
 *  --print           Show debug information
 *  --install-alias   Install 'claude' alias in your shell configuration
 */

const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");
const crypto = require("crypto");
const os = require("os");
const { execSync } = require("child_process");

// Get version from package.json
const packageJson = require("./package.json");
const version = packageJson.version;

// Help text function
function showHelp() {
  console.log(
    `
Claude Logger - Captures Claude API requests and responses
Usage: claude-log [options] [claude options]

Options:
  --help          Show this help message and then continue with the command
  --log_dir=DIR   Specify directory for logs (default: ./logs)
  --print         Show debug information
  --install-alias Install 'claude' alias in your shell configuration

The claude-log command passes all other arguments to the claude CLI.
`
  );
}

// Parse command line arguments
const args = process.argv.slice(2);
let logDir = null;
let projectLogEnabled = true;
let printDebug = false;
let showHelpMessage = false;
let installAlias = false;
let claudeArgs = [];

// Process arguments
for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (arg === "--help") {
    showHelpMessage = true;
    claudeArgs.push(arg); // Pass --help to Claude
  } else if (arg.startsWith("--log_dir=")) {
    logDir = arg.split("=")[1];
  } else if (arg === "--log_dir" && i < args.length - 1) {
    logDir = args[i + 1];
    i++;
  } else if (arg === "--print") {
    printDebug = true;
  } else if (arg === "--install-alias") {
    installAlias = true;
  } else if (arg === "--no-project-log") {
    console.log("Error: --no-project-log is no longer supported as project logs are the only option.");
    process.exit(1);
  } else {
    claudeArgs.push(arg);
  }
}

// Show help if requested but continue execution
if (showHelpMessage) {
  showHelp();
}

// Install alias if requested
if (installAlias) {
  if (installClaudeAlias()) {
    if (claudeArgs.length === 0) {
      // If no other arguments were provided, exit after installing alias
      process.exit(0);
    }
    // Otherwise continue with normal operation
  }
}

// Get current working directory (project directory)
const cwd = process.cwd();
const projectName = path.basename(cwd);

// Generate session ID - used to maintain log file continuity across help usage
const sessionId = process.env.CLAUDE_LOGGER_SESSION_ID || (() => {
  const now = new Date();
  const timestamp = now.toISOString()
    .replace(/:/g, "-")
    .replace("T", "-")
    .replace(/\.\d+Z$/, "");
  return `${timestamp}_${crypto.randomBytes(4).toString("hex")}`;
})();

// Determine log directory - use specified log_dir if provided, otherwise use project directory
const projectLogsDir = logDir ? logDir : path.join(cwd, "logs");
if (!fs.existsSync(projectLogsDir)) {
  fs.mkdirSync(projectLogsDir, { recursive: true });
}

// Create log file with consistent naming across the session
const logFile = path.join(projectLogsDir, `${projectName}_${sessionId}.json`);

// Check if this is the first time we're accessing this log file
const isNewLogFile = !fs.existsSync(logFile);

// Create or append to the log file
try {
  // Initialize file if it doesn't exist yet
  if (isNewLogFile) {
    fs.writeFileSync(logFile, "[]");
  }
  
  // Position the help message adjacent to user-facing logs by appending to existing log files
  if (showHelpMessage && !isNewLogFile) {
    // For JSON log, we don't need to do anything since it only captures API calls
  }
  
  if (printDebug) {
    console.log(`Logs will be saved to: ${logFile}`);
  }
} catch (err) {
  console.error(`Error: Cannot write to log file: ${err.message}`);
  process.exit(1);
}

// Check if this is the first run in the project
checkForFirstRunAndSuggestAlias();

console.log(
  `Claude Logger v${version} - Starting Claude` +
    (claudeArgs.includes("-p") ? " with prompt" : " in interactive mode")
);
console.log(`Logs will be ${isNewLogFile ? 'created at' : 'appended to'}: ${logFile}`);

// Run Claude with our direct_capture.js module loaded to intercept requests
console.log("Initializing request capture...");

// Set up environment for direct_capture.js
const existingNodeOptions = process.env.NODE_OPTIONS || "";
const captureEnv = {
  ...process.env,
  CLAUDE_API_LOG_FILE: logFile,
  CLAUDE_PROJECT_NAME: projectName,
  CLAUDE_DEBUG: printDebug ? "true" : "false",
  CLAUDE_LOGGER_VERSION: version,
  CLAUDE_LOGGER_SESSION_ID: sessionId, // Pass session ID for consistency across runs
  NODE_OPTIONS: `${existingNodeOptions} --require "${path.join(__dirname, "direct_capture.js")}"`.trim(),
};

if (printDebug) {
  console.log("NODE_OPTIONS:", captureEnv.NODE_OPTIONS);
}

// Fix for cursor position - pass stdin directly to the claude process
// and use stdio: 'inherit' for stdout so that terminal control sequences work properly
const claudeProcess = spawn("claude", claudeArgs, {
  env: captureEnv,
  stdio: ["inherit", "inherit", "pipe"], // Pass stdin and stdout directly, only capture stderr
});

// Capture and filter stderr (to hide debug messages when not in debug mode)
let stderrBuffer = "";
claudeProcess.stderr.on("data", (data) => {
  const text = data.toString();
  stderrBuffer += text;

  // Only print stderr if it's not debug output or if debug mode is enabled
  if (
    printDebug ||
    (!text.includes("DEBUG:") &&
      !text.includes("intercepted") &&
      !text.includes("Intercepted") &&
      !text.includes("Environment Variables"))
  ) {
    process.stderr.write(data);
  }
});

// Handle process exit
claudeProcess.on("close", (code) => {
  // Give the child process time to flush logs
  setTimeout(() => {
    console.log(`Logs written to ${logFile}`);
    process.exit(code);
  }, 100);
});

claudeProcess.on("error", (err) => {
  console.log(`Logs written to ${logFile}`);
  console.error(`Error running Claude: ${err.message}`);
  process.exit(1);
});

/**
 * Installs the 'claude' alias to the user's shell configuration file
 * @returns {boolean} - True if alias was installed successfully, false otherwise
 */
function installClaudeAlias() {
  const homeDir = os.homedir();
  
  // Detect shell type
  let shellType = '';
  try {
    const shell = process.env.SHELL || '';
    if (shell.includes('zsh')) shellType = 'zsh';
    else if (shell.includes('bash')) shellType = 'bash';
    else if (shell.includes('fish')) shellType = 'fish';
  } catch (err) {
    // Default to bash if detection fails
    shellType = 'bash';
  }
  
  // Determine appropriate config file
  let configFile = '';
  let installCommands = '';
  
  if (shellType === 'zsh') {
    configFile = path.join(homeDir, '.zshrc');
    installCommands = "\n# Claude CLI alias for logging\nalias claude='claude-log'\n";
  } else if (shellType === 'fish') {
    configFile = path.join(homeDir, '.config', 'fish', 'config.fish');
    installCommands = "\n# Claude CLI alias for logging\nalias claude='claude-log'\n";
  } else {
    // Default to bash
    configFile = path.join(homeDir, '.bashrc');
    // Check if .bash_profile exists and prefer it on macOS
    const bashProfile = path.join(homeDir, '.bash_profile');
    if (fs.existsSync(bashProfile) && process.platform === 'darwin') {
      configFile = bashProfile;
    }
    installCommands = "\n# Claude CLI alias for logging\nalias claude='claude-log'\n";
  }
  
  try {
    // Create directory if it doesn't exist (particularly for Fish)
    if (shellType === 'fish') {
      const configDir = path.dirname(configFile);
      if (!fs.existsSync(configDir)) {
        fs.mkdirSync(configDir, { recursive: true });
      }
    }
    
    // Check if file exists
    if (!fs.existsSync(configFile)) {
      // Create file if it doesn't exist
      fs.writeFileSync(configFile, installCommands);
    } else {
      // Check if alias already exists
      const content = fs.readFileSync(configFile, 'utf8');
      if (!content.includes("alias claude='claude-log'")) {
        // Append alias to file
        fs.appendFileSync(configFile, installCommands);
      } else {
        console.log("The 'claude' alias is already installed in your shell configuration.");
        return true;
      }
    }
    
    // Output additional instructions for Fish shell
    if (shellType === 'fish') {
      console.log("\n✅ Alias installed! For Fish shell, you may also need to run:");
      console.log("   funcsave claude");
    }
    
    console.log(`\n✅ The 'claude' alias has been installed in ${configFile}`);
    console.log("   You'll need to restart your terminal or run the following to use it now:");
    
    if (shellType === 'fish') {
      console.log(`   source ${configFile}`);
    } else {
      console.log(`   source ${configFile}`);
    }
    
    return true;
  } catch (err) {
    console.error(`Error installing alias: ${err.message}`);
    return false;
  }
}

/**
 * Checks if this is the first run in a project directory and suggests setting
 * up the claude alias if it's not already set up
 */
function checkForFirstRunAndSuggestAlias() {
  // Only suggest if this appears to be the first run in this project
  const isFirstProjectRun = !fs.existsSync(path.join(cwd, "logs")) || 
                            fs.readdirSync(path.join(cwd, "logs")).length === 0;
  
  if (!isFirstProjectRun) {
    return;
  }
  
  // Check for the alias in common shell config files
  const homeDir = os.homedir();
  const configFiles = [
    { path: path.join(homeDir, ".bashrc"), type: "bash" },
    { path: path.join(homeDir, ".bash_profile"), type: "bash" },
    { path: path.join(homeDir, ".zshrc"), type: "zsh" },
    { path: path.join(homeDir, ".config", "fish", "config.fish"), type: "fish" }
  ];
  
  let aliasFound = false;
  
  for (const config of configFiles) {
    if (fs.existsSync(config.path)) {
      try {
        const content = fs.readFileSync(config.path, "utf8");
        if (content.includes("alias claude='claude-log'")) {
          aliasFound = true;
          break;
        }
      } catch (err) {
        // Skip if we can't read the file
      }
    }
  }
  
  if (!aliasFound) {
    console.log("\n========================================================");
    console.log("💡 First time using claude-logger in this project!");
    console.log("   For convenience, you can set up an alias in your shell:");
    console.log("");
    console.log("   For Bash/Zsh (add to .bashrc or .zshrc):");
    console.log("   alias claude='claude-log'");
    console.log("");
    console.log("   For Fish shell:");
    console.log("   alias claude='claude-log'");
    console.log("   funcsave claude");
    console.log("========================================================\n");
  }
}
