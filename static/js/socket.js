const socket = io({
    transports: ["websocket", "polling"]
});

socket.on("connect", () => {
    console.log("Socket connected:", socket.id);
});

socket.on("new_log", (data) => {

    console.log("LOG RECEIVED:", data); // DEBUG (VERY IMPORTANT)

    const logs = document.getElementById("logs");

    if (!logs) return;

    const logEntry = document.createElement("div");
    logEntry.classList.add("log-entry");

    logEntry.innerHTML = `
        <div class="log-message">${data.message}</div>
        <div class="log-time">${data.time}</div>
    `;

    logs.prepend(logEntry);
});
