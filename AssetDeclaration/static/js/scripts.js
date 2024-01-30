/*!
    * Start Bootstrap - SB Admin v7.0.7 (https://startbootstrap.com/template/sb-admin)
    * Copyright 2013-2023 Start Bootstrap
    * Licensed under MIT (https://github.com/StartBootstrap/startbootstrap-sb-admin/blob/master/LICENSE)
    */
//
// Scripts
// 

document.addEventListener('DOMContentLoaded', function () {
    // Toggle the side navigation
    const sidebarToggle = document.body.querySelector('#sidebarToggle');
    if (sidebarToggle) {
        sidebarToggle.addEventListener('click', event => {
            event.preventDefault();
            document.body.classList.toggle('sb-sidenav-toggled');
            localStorage.setItem('sb|sidebar-toggle', document.body.classList.contains('sb-sidenav-toggled'));
        });
    }

    // New script for User-Admin-Approval functionality
    function loadUserApprovalData() {
        // This function should contain the same code as the one in user_admin_approval.html
        // to fetch and display user data for approval
        // ...
    }

    function approveUser(userId) {
        // This function should contain the same code as the one in user_admin_approval.html
        // to handle user approval (server-side logic)
        // ...
    }

    function rejectUser(userId) {
        // This function should contain the same code as the one in user_admin_approval.html
        // to handle user rejection (server-side logic)
        // ...
    }

    // Function to handle asset action (approve/reject)
    function handleAssetAction(assetId, action) {
        console.log(`${action} button clicked for asset ID: ${assetId}`);

        // Send a request to perform the asset action
        fetch(`/${action}_asset`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ asset_id: assetId }),
        })
        .then(response => {
            if (response.ok) {
                console.log(`Asset ${action}ed successfully`);
                // You can update the UI here if needed
            } else {
                console.error(`Error ${action}ing asset:`, response.statusText);
                // Handle the error appropriately
            }
        })
        .catch(error => {
            console.error(`Error ${action}ing asset:`, error);
            // Handle the error appropriately
        });
    }

    // Get all approve and reject buttons
    const actionButtons = document.querySelectorAll('.approve-btn, .reject-btn');

    // Add click event listener to each action button
    actionButtons.forEach(button => {
        button.addEventListener('click', function () {
            // Get the asset ID from the data-id attribute
            const assetId = this.getAttribute('data-id');

            // Determine the action based on the button's class
            const action = this.classList.contains('approve-btn') ? 'approve' : 'reject';

            // Handle the asset action
            handleAssetAction(assetId, action);
        });
    });

    // Load user approval data when the page is loaded
    loadUserApprovalData();
});
