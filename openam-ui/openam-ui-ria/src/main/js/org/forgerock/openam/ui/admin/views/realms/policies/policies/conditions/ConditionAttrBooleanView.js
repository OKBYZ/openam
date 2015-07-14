/**
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2015 ForgeRock AS.
 */

/*global define*/

define("org/forgerock/openam/ui/admin/views/realms/policies/policies/conditions/ConditionAttrBooleanView", [
    "jquery",
    "underscore",
    "org/forgerock/openam/ui/admin/views/realms/policies/policies/conditions/ConditionAttrBaseView"
], function ($, _, ConditionAttrBaseView) {
    return ConditionAttrBaseView.extend({
        template: "templates/admin/views/realms/policies/policies/conditions/ConditionAttrBoolean.html",

        render: function (data, element, callback) {
            this.initBasic(data, element, "field-float-pattern data-obj button-field");

            this.events["click .btn"] = _.bind(this.buttonControlClick, this);
            this.events["keyup .btn"] = _.bind(this.buttonControlClick, this);

            this.parentRender(function () {
                if (callback) {
                    callback();
                }
            });
        },

        buttonControlClick: function (e) {
            if (e.type === "keyup" && e.keyCode !== 13) {
                return;
            }

            var target = $(e.currentTarget),
                buttonControl = target.closest(".btn-group"),
                label = buttonControl.prev("label").data().title,
                secondButton = buttonControl.find(".btn.btn-primary");

            if (target.hasClass("btn-primary")) {
                return;
            }

            this.data.itemData[label] = target.data("val");

            secondButton.removeClass("btn-primary");
            secondButton.addClass("btn-default");

            target.addClass("btn-primary");
            target.removeClass("btn-default");
        }
    });
});