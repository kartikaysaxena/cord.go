package errorhandler

import (
	"github.com/kartikaysaxena/cord.go/packages/types/extrinsic"
)

func ExtrinsicFailed(extrinsicResult extrinsic.ISubmittableResult) bool {
	for _, eventDetails := range extrinsicResult.Events {
		if eventDetails.Event.Section == "system" && eventDetails.Event.Method == "ExtrinsicFailed" {
			return true
		}
	}
	return false
}

func ExtrinsicSuccessful(extrinsicResult extrinsic.ISubmittableResult) bool {
	for _, event := range extrinsicResult.Events {
		if event.Event.Section == "system" && event.Event.Method == "ExtrinsicSuccess" {
			return true
		}
	}
	return false
}

// func ExtrinsicError(extrinsicResult extrinsic.ISubmittableResult) interface{} { // revisit
// 	errorEvent := extrinsicResult.DispactchError

// 	if errorEvent != nil && errorEvent.IsModule {
// 		moduleError := errorEvent.ModuleError.Error
// 		return moduleError
// 	}

// 	return nil
// }
