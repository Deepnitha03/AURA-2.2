
document.addEventListener("DOMContentLoaded", function () {

    // ===============================
    // AURA-2.2 START SCAN
    // ===============================

    const startScanBtn = document.getElementById("startScanBtn");
    const scanStatus = document.getElementById("scanStatus");

    // Summary card elements

    const totalEndpoints = document.getElementById("totalEndpoints");
    const testedEndpoints = document.getElementById("testedEndpoints");
    const vulnerableEndpoints = document.getElementById("vulnerableEndpoints");
    const passedEndpoints = document.getElementById("passedEndpoints");

    if (startScanBtn && scanStatus) {

        startScanBtn.addEventListener("click", function () {

            scanStatus.textContent = "Scanning authorized demo target...";

            startScanBtn.textContent = "Scanning...";
            startScanBtn.disabled = true;

            setTimeout(function () {

                
// Simulated demo results

if (
    totalEndpoints &&
    testedEndpoints &&
    vulnerableEndpoints &&
    passedEndpoints
) {

    totalEndpoints.textContent = "10";
    testedEndpoints.textContent = "10";
    vulnerableEndpoints.textContent = "2";
    passedEndpoints.textContent = "8";

}

// Update endpoint findings table

const resultsTable = document.getElementById("resultsTable");

if (resultsTable) {

    resultsTable.innerHTML = `
        <tr>
            <td>BOLA</td>
            <td>/api/users/{id}</td>
            <td><span class="high">High</span></td>
            <td>Detected</td>
        </tr>

        <tr>
            <td>BFLA</td>
            <td>/api/admin</td>
            <td><span class="medium">Medium</span></td>
            <td>Detected</td>
        </tr>
    `;

}

                scanStatus.textContent =
                    "Demo scan completed. Backend connection is pending.";

                startScanBtn.textContent = "Start Scan";
                startScanBtn.disabled = false;

            }, 2000);
        });

    } else {
        console.warn("Start Scan elements not found.");
    }


    // ===============================
    // AURA-2.2 REGRESSION TESTING
    // ===============================

    const regressionBtn = document.getElementById("regressionBtn");
    const regressionStatus = document.getElementById("regressionStatus");

    console.log("Regression Button:", regressionBtn);
    console.log("Regression Status:", regressionStatus);

    if (regressionBtn && regressionStatus) {

        regressionBtn.addEventListener("click", function () {

            regressionStatus.textContent =
                "Running demo regression test...";

            regressionStatus.className = "";

            regressionBtn.textContent = "Testing...";
            regressionBtn.disabled = true;

            setTimeout(function () {

                // Simulated demonstration results

                const previousStatus = 200;
                const currentStatus = 403;

                if (previousStatus === 200 && currentStatus === 403) {

                    regressionStatus.textContent =
                        "✓ DEMO PASSED — Authorization check appears fixed.";

                    regressionStatus.className = "success";

                } else {

                    regressionStatus.textContent =
                        "✗ DEMO FAILED — Authorization check needs review.";

                    regressionStatus.className = "failed";
                }

                regressionBtn.textContent = "Run Regression Test";
                regressionBtn.disabled = false;

            }, 2000);

        });

    } else {

        console.warn("Regression elements not found. Check HTML IDs.");

    }

});