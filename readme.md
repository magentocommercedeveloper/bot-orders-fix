# Ssquare_Security Magento 2 Module

## Overview
The `Ssquare_Security` module for Magento 2 is designed to enhance the security of your checkout process by restricting input fields from accepting potentially harmful content. It prevents the acceptance of HTML, CSS, JavaScript, jQuery, Magento template directives, and suspicious code sequences often used in command injections.

## Features
- Restricts checkout fields from accepting HTML, CSS, JS, jQuery, and regular expressions.
- Blocks Magento template directives (e.g., `{{var this.getTemplateFilter().filter(order)}}`).
- Detects and blocks suspicious command sequences (e.g., `cd${IFS%??}pub;curl${IFS%??}-o...`).

## Installation

### Via Composer
1. Navigate to your Magento 2 root directory.
2. Run the following commands:

```bash
composer require ssquare/security
php bin/magento module:enable Ssquare_Security
php bin/magento setup:upgrade
php bin/magento cache:clean
