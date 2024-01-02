/*!
    * Start Bootstrap - SB Admin v7.0.7 (https://startbootstrap.com/template/sb-admin)
    * Copyright 2013-2023 Start Bootstrap
    * Licensed under MIT (https://github.com/StartBootstrap/startbootstrap-sb-admin/blob/master/LICENSE)
    */
//
// Scripts
// 

window.addEventListener('DOMContentLoaded', event => {

    // Toggle the side navigation
    const sidebarToggle = document.body.querySelector('#sidebarToggle');
    if (sidebarToggle) {
        // Uncomment Below to persist sidebar toggle between refreshes
        // if (localStorage.getItem('sb|sidebar-toggle') === 'true') {
        //     document.body.classList.toggle('sb-sidenav-toggled');
        // }
        sidebarToggle.addEventListener('click', event => {
            event.preventDefault();
            document.body.classList.toggle('sb-sidenav-toggled');
            localStorage.setItem('sb|sidebar-toggle', document.body.classList.contains('sb-sidenav-toggled'));
        });
    }
// Your existing scripts (unchanged)

// New script for User-Admin-Approval functionality
// (you can include this in the existing scripts.js file or use a separate file)
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

});
