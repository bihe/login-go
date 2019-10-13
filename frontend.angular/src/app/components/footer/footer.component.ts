import { Component, OnInit, VERSION } from '@angular/core';
import { MatSnackBar } from '@angular/material';
import { ApiAppInfoService } from '../../shared/service/api.app.service';
import { MessageUtils } from '../../shared/utils/message.utils';
import { AppInfo } from '../../shared/service/app.info.model';
import { ApplicationState } from '../../shared/service/application.state';

@Component({
  selector: 'app-footer',
  templateUrl: './footer.component.html',
  styleUrls: ['./footer.component.css']
})
export class FooterComponent implements OnInit {

  appData: AppInfo;
  year: number = new Date().getFullYear();

  constructor(
    private appInfoService: ApiAppInfoService,
    private appState: ApplicationState,
    private snackBar: MatSnackBar
  ) {}

  ngOnInit(): void {
    this.appInfoService.getApplicationInfo()
      .subscribe(
        data => {
          this.appData = data;
          this.appData.uiRuntime = 'angular=' + VERSION.full;

          this.appState.setAppInfo(data);
        },
        error => {
          console.log('Error: ' + error);
          new MessageUtils().showError(this.snackBar, error);
        }
      );
  }
}
