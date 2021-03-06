#pragma once

#include <QSystemTrayIcon>
#include <QDialog>
#include <QSettings>

class QAction;
class QLabel;
class QLineEdit;
class QMenu;
class QPushButton;
class ConfigGui;

#include "ui_dbpassguiui.h"

class DbPassGui : public QDialog, public Ui_DbPassGui
{
	Q_OBJECT

public:
	DbPassGui(QWidget * parent = 0);

	void setVisible(bool visible);
	bool eventFilter(QObject *obj, QEvent *event);

public slots:
	void showNormal();
	void hide();

protected:
	void closeEvent(QCloseEvent *event);
	void loadSeversFromFile(QString filename);
private slots:
	void iconActivated(QSystemTrayIcon::ActivationReason reason);
	void generatePressed();
	void flipCheckBoxA(int);
	void flipCheckBoxB(int);
	
	void hostnameEntered();
	void sidEntered();
	void hostnameCleared(const QString &);
	void sidCleared(const QString &);
	void clearAll();

	void showConfigDialog();
	void refreshConfig(QString filename);
private:
	void createActions();
	void createTrayIcon();
	void setDbid(QString const&);

	QAction *minimizeAction;
	QAction *configureAction;
	QAction *openAction;
	QAction *quitAction;

	QIcon *icon;
	QSystemTrayIcon *trayIcon;
	QMenu *trayIconMenu;

	ConfigGui *config;

	QSettings settings;
	QString n;
	QMap<QString, QMap<QString, QString> > hostSidToDbid, sidHostToDbid;
};
