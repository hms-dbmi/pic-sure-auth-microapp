define(["backbone","handlebars",  "application/addApplication", "text!application/applicationManagement.hbs", "text!application/applicationMenu.hbs", "text!application/applicationTable.hbs", "text!options/modal.hbs", "picSure/applicationFunctions", "util/notification","picSure/applicationFunctions"],
		function(BB, HBS, AddApplicationView, template, applicationMenuTemplate, applicationTableTemplate, modalTemplate, applicationFunctions, notification, applicationFunctions){
	var applicationManagementModel = BB.Model.extend({
	});

	var applicationManagementView = BB.View.extend({
		// connections : connections,
		template : HBS.compile(template),
		crudApplicationTemplate : HBS.compile(applicationMenuTemplate),
		modalTemplate : HBS.compile(modalTemplate),
		initialize : function(opts){
			HBS.registerHelper('fieldHelper', function(application, connectionField){
				if (application.generalMetadata == null || application.generalMetadata === '') {
                    return "NO_GENERAL_METADATA";
                }
                else {
					return JSON.parse(application.generalMetadata)[connectionField.id];
				}
			});
            HBS.registerHelper('displayEmail', function(application){
				var c = application.connectionId;
                var emailField = _.where(connections, {id: application.connectionId})[0].emailField;
				if (!application.email) {
                    return JSON.parse(application.generalMetadata)[emailField];
				}
                return application.email;
            });
		},
		events : {
			"click .add-application-button":   "addApplicationMenu",
			"click #edit-application-button":  "editApplicationMenu",
			"click .close":             "closeDialog",
			"click #cancel-application-button":"closeDialog",
			"click .application-row":          "showApplicationAction",
			"click #delete-application-button":"deleteApplication",
			"submit":                   "saveApplicationAction",
		},
		displayApplications: function (result, view) {
			this.applicationTableTemplate = HBS.compile(applicationTableTemplate);
			$('.application-data', this.$el).html(this.applicationTableTemplate({applications:result}));

		},
		addApplicationMenu: function (result) {
			applicationFunctions.fetchApplications(this, function(applications,view){
				view.showAddApplicationMenu({applications : applications}, view);
			});
		},
		showAddApplicationMenu: function(result, view) {
            $("#modal-window", this.$el).html(this.modalTemplate({title: "Add Application"}));
            $("#modalDialog", this.$el).show();
            var addApplicationView = new AddApplicationView({el:$('.modal-body'), managementConsole: this, applications:result}).render();
		},
		editApplicationMenu: function (events) {
			$(".modal-body", this.$el).html(this.crudApplicationTemplate({createOrUpdateApplication: true, application: this.model.get("selectedApplication")}));
			// this.applyCheckboxes();
		},
		// applyCheckboxes: function () {
		// 	var checkBoxes = $(":checkbox", this.$el);
		// 	var applicationApplications = this.model.get("selectedApplication").applications;
		// 	_.each(checkBoxes, function (applicationCheckbox) {
		// 		if (applicationApplications.includes(applicationCheckbox.value)){
		// 			applicationCheckbox.checked = true;
		// 		}
		// 	})
		// },
		showApplicationAction: function (event) {
			var uuid = event.target.id;

			applicationFunctions.showApplicationDetails(uuid, function(result) {
				this.model.set("selectedApplication", result);
				$("#modal-window", this.$el).html(this.modalTemplate({title: "Application Info"}));
				$("#modalDialog", this.$el).show();
				$(".modal-body", this.$el).html(this.crudApplicationTemplate({createOrUpdateApplication: false, application: this.model.get("selectedApplication")}));
			}.bind(this));
		},
        applyCheckboxes: function () {
            var checkBoxes = $(":checkbox", this.$el);
            var applicationRoles = this.model.get("selectedApplication").roles;
            _.each(checkBoxes, function (roleCheckbox) {
                _.each(applicationRoles, function(role){
                    if (role.name === roleCheckbox.name){
                        roleCheckbox.checked = true;
                    }
                });
            })
        },
        saveApplicationAction: function (e) {
            e.preventDefault();
            var uuid = this.$('input[name=application_name]').attr('uuid');
            var name = this.$('input[name=application_name]').val();
            var description = this.$('input[name=application_description]').val();

            var application;
            var requestType;
            if (this.model.get("selectedApplication") != null && this.model.get("selectedApplication").uuid.trim().length > 0) {
                requestType = "PUT";
            }
            else {
                requestType = "POST";
            }

            application = [{
                uuid: uuid,
                name: name,
                description: description
            }];

            applicationFunctions.createOrUpdateApplication(application, requestType, function(result) {
                console.log(result);
                this.render();
            }.bind(this));
        },
		deleteApplication: function (event) {
			var uuid = this.$('input[name=application_name]').attr('uuid');
			notification.showConfirmationDialog(function () {

				applicationFunctions.deleteApplication(uuid, function (response) {
					this.render()
				}.bind(this));

			}.bind(this));
		},
		// getApplicationApplications: function (stringApplications) {
		// 	var applications = stringApplications.split(",").map(function(item) {
		// 		return item.trim();
		// 	});
		// 	this.model.get("selectedApplication").applications = applications;
		// },
		closeDialog: function () {
			// cleanup
			this.model.unset("selectedApplication");
			$("#modalDialog").hide();
		},
		render : function(){
			this.$el.html(this.template({}));
			// applicationFunctions.getAvailableApplications(function (applications) {
			// 	this.model.set("availableApplications", applications);
			// }.bind(this));
			applicationFunctions.fetchApplications(this, function(applications){
				this.displayApplications.bind(this)
				(
						applications
				);
			}.bind(this));
		}
	});

	return {
		View : applicationManagementView,
		Model: applicationManagementModel
	};
});