<?php
// app/code/Ssquare/Security/Plugin/ValidateCheckoutInput.php

namespace Ssquare\Security\Plugin;

use Magento\Checkout\Model\Session as CheckoutSession;
use Magento\Framework\Exception\LocalizedException;

class ValidateCheckoutInput
{
    protected $checkoutSession;

    public function __construct(CheckoutSession $checkoutSession)
    {
        $this->checkoutSession = $checkoutSession;
    }

    public function beforeSaveAddressInformation(
        \Magento\Checkout\Model\ShippingInformationManagement $subject,
        $cartId,
        \Magento\Checkout\Api\Data\ShippingInformationInterface $addressInformation
    ) {
        $this->validateAddressData($addressInformation->getShippingAddress()->getData());
        $this->validateAddressData($addressInformation->getBillingAddress()->getData());
    }

    protected function validateAddressData($addressData)
    {
        foreach ($addressData as $key => $value) {
            if (is_string($value)) {
                if ($this->containsHtml($value) || $this->containsJs($value) || $this->containsCss($value) || $this->containsMagentoTemplateDirective($value) || $this->containsSuspiciousCode($value)) {
                    throw new LocalizedException(
                        __('Invalid input detected in the field: %1', $key)
                    );
                }
            }
        }
    }

    protected function containsHtml($value)
    {
        return $value !== strip_tags($value);
    }

    protected function containsJs($value)
    {
        $jsPatterns = [
            '/<script\b[^>]*>(.*?)<\/script>/is',
            '/on\w*=["\'].*["\']/i', // Inline event handlers
            '/javascript:/i'
        ];

        foreach ($jsPatterns as $pattern) {
            if (preg_match($pattern, $value)) {
                return true;
            }
        }

        return false;
    }

    protected function containsCss($value)
    {
        // This will detect any inline styles or style tags
        $cssPatterns = [
            '/<style\b[^>]*>(.*?)<\/style>/is',
            '/style\s*=\s*["\'].*["\']/i'
        ];

        foreach ($cssPatterns as $pattern) {
            if (preg_match($pattern, $value)) {
                return true;
            }
        }

        return false;
    }

    protected function containsMagentoTemplateDirective($value)
    {
        // Detect Magento template directives
        $templatePattern = '/\{\{.*?\}\}/';

        if (preg_match($templatePattern, $value)) {
            return true;
        }

        return false;
    }

    protected function containsSuspiciousCode($value)
    {
        // Detect command injection patterns or suspicious code sequences
        $suspiciousPatterns = [
            '/cd\${IFS%??}pub;/i', // Detecting specific suspicious sequences
            '/curl\${IFS%??}-o\${IFS%??}/i', // Detecting curl command in a suspicious way
            '/\$\(.*\)/' // Detecting possible command substitution
        ];

        foreach ($suspiciousPatterns as $pattern) {
            if (preg_match($pattern, $value)) {
                return true;
            }
        }

        return false;
    }
}
