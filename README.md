
# EguibarIT.DelegationPS - Simplifying Active Directory Delegation

[![PowerShell Gallery Version](https://img.shields.io/powershellgallery/v/EguibarIT.DelegationPS.svg)](https://www.powershellgallery.com/packages/EguibarIT.DelegationPS) [![PowerShell Gallery Preview Version](https://img.shields.io/powershellgallery/vpre/EguibarIT.DelegationPS.svg?label=powershell%20gallery%20preview&colorB=yellow)](https://www.powershellgallery.com/packages/EguibarIT.DelegationPS) [![GitHub License](https://img.shields.io/github/license/vreguibar/EguibarIT.DelegationPS.svg)](https://github.com/vreguibar/EguibarIT.DelegationPS)

[![PowerShell Gallery](https://img.shields.io/powershellgallery/p/EguibarIT.DelegationPS.svg)](https://www.powershellgallery.com/packages/EguibarIT.DelegationPS) [![GitHub Top Language](https://img.shields.io/github/languages/top/vreguibar/EguibarIT.DelegationPS.svg)](https://github.com/vreguibar/EguibarIT.DelegationPS) [![GitHub Code Size](https://img.shields.io/github/languages/code-size/vreguibar/EguibarIT.DelegationPS.svg)](https://github.com/vreguibar/EguibarIT.DelegationPS) [![PowerShell Gallery Downloads](https://img.shields.io/powershellgallery/dt/EguibarIT.DelegationPS.svg)](https://www.powershellgallery.com/packages/EguibarIT.DelegationPS)

[![LinkedIn](https://img.shields.io/badge/LinkedIn-VicenteRodriguezEguibar-0077B5.svg?logo=LinkedIn)](https://www.linkedin.com/in/VicenteRodriguezEguibar)

## Overview

The EguibarIT.DelegationPS module is a powerful tool for managing access control and delegation within your Active Directory (AD) environment. Whether you’re an IT administrator, security professional, or system architect, this module streamlines the process of defining roles, permissions, and administrative boundaries.

## Key Features

- Role-Based Access Control (RBAC):
-- The module introduces a Tier Model and a Delegation Model to organize administrative tasks.
-- RBAC ensures that users have the right permissions based on their roles, minimizing security risks.

- Components:
--Administration Organizational Unit (OU) (Tier 0):
--Represents the highest level of administrative control.
--Contains groups corresponding to specific roles (e.g., Domain Admins, Help Desk).

- Servers OU (Tier 1):
--Organizes servers based on function (e.g., File Servers, Web Servers).
--Each server group inherits permissions from the Administration OU.

- Sites OU (Tier 2):
--Represents geographical or logical groupings of servers.
--Further refines permissions based on site-specific needs.

## Basic Functions

The module provides essential functions for creating and managing the above components.

Examples include:

New-DelegationRoleGroup: Creates role-based groups within the Administration OU.

Set-ServerPermissions: Assigns permissions to servers based on their OU membership.

## Best Practices

Follow industry best practices for delegation:

Limit permissions to what’s necessary for each role.

Regularly review and adjust permissions.

Document the delegation structure.

## Set corresponding permissions to AD for the Delegation Model / Tier Model (PowerShell based)

This code is used to create and modify SACL and DACL for the Delegation Model / Tier Model / RBAC model

The AD Delegation Model (also known as [Role Based Access Control](http://eguibarit.eu/microsoft/active-directory/role-based-access-control/), or simply [RBAC](http://eguibarit.eu/microsoft/active-directory/role-based-access-control/)) is the implementation of: [Least Privileged Access](http://eguibarit.eu/least-privileged-access/), [Segregation of Duties](http://eguibarit.eu/segregation-of-duties/) and “[0 (zero) Admin](http://eguibarit.eu/0-admin-model/)“. By identifying the tasks that execute against Active Directory, we can categorize and organize in a set of functional groups, or roles. Those roles can be dynamically assigned to the [Semi-Privileged accounts](http://eguibarit.eu/privileged-semi-privileged-users/). This reduces the exposed rights by having what needs, and does provides an easy but effective auditing of rights. The model does helps reduce the running costs by increasing efficiency. Additionally increases the overall security of the directory, adhering to industry best practices.

The goal is to determine the effective performance of computer management. Designing a directory that supports an efficient and simple organic functionality of the company. Anyone can “transfer” the organigram of the company to AD, but often, will not provide any extra management benefit. Even worse, it may complicate it. Not to talk about security or [segregation of duties and assets](http://eguibarit.eu/segregation-of-duties/). Eguibar Information Technology S.L. can design the Active Directory based on the actual needs of the company focusing on computer management model. This benefits of the processes necessary for the daily management,  being more efficient, reducing maintenance costs and providing a high degree of security.

![AD Delegation Model](https://eguibarit.eu/wp-content/uploads/2017/09/Security-Boundary-1024x735.jpg)
